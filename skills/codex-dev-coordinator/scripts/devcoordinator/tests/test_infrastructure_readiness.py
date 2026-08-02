"""Failure-shaped tests for central Windows-observer readiness export."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from devcoordinator.broker_persistence import BrokerPersistence
from devcoordinator.infrastructure_observation import (
    InfrastructureObservationAuthority,
)
from devcoordinator.infrastructure_readiness import (
    CENTRAL_READINESS_SCHEMA,
    CentralReadinessInputs,
    InfrastructureReadinessError,
    _validate_current_enrollment,
    export_observer_central_readiness,
)
from devcoordinator.store import CoordinatorStore, canonical_json


class InfrastructureReadinessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix=".infrastructure-readiness-",
            dir="/tmp",
        )
        self.root = Path(self.temporary.name)
        self.now = int(datetime.now(tz=timezone.utc).timestamp())
        self.database = self.root / "coordinator.sqlite3"
        with CoordinatorStore.open(self.database):
            pass
        self.database.chmod(0o600)
        self.cell_id = str(uuid.uuid4())
        self.host_id = str(uuid.uuid4())
        self.agent_id = str(uuid.uuid4())
        self.vm_id = str(uuid.uuid4())
        self.ingress_uid = 12345
        self.reader_uid = 12346

        self.client_ca_key, self.client_ca = self.make_ca("Client fixture CA")
        self.server_ca_key, self.server_ca = self.make_ca("Server fixture CA")
        self.client_key, self.client_leaf = self.make_leaf(
            issuer_key=self.client_ca_key,
            issuer=self.client_ca,
            eku=ExtendedKeyUsageOID.CLIENT_AUTH,
            common_name="SPECTRE observer",
        )
        self.server_key, self.server_leaf = self.make_leaf(
            issuer_key=self.server_ca_key,
            issuer=self.server_ca,
            eku=ExtendedKeyUsageOID.SERVER_AUTH,
            common_name="spectre.classified.guru",
            dns_name="spectre.classified.guru",
        )
        self.client_crl = self.make_crl(
            issuer_key=self.client_ca_key,
            issuer=self.client_ca,
        )
        self.jws_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072,
        )
        self.jws_spki = self.jws_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.jws_spki_sha256 = hashlib.sha256(self.jws_spki).hexdigest()
        self.client_der = self.client_leaf.public_bytes(
            serialization.Encoding.DER
        )
        self.client_fingerprint = hashlib.sha256(self.client_der).hexdigest()
        self.valid_from = int(self.client_leaf.not_valid_before_utc.timestamp())
        self.valid_until = int(self.client_leaf.not_valid_after_utc.timestamp())

        self.receipt_paths = self.create_authority_receipts()
        self.write_pki()
        self.socket_path = self.root / "broker.sock"
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.bind(str(self.socket_path))
        self.socket_path.chmod(0o660)
        self.authority_generation = self.database_generation()
        self.config_path = self.write_config()
        self.output = self.root / "central-readiness.json"

    def tearDown(self) -> None:
        self.socket.close()
        self.temporary.cleanup()

    def make_ca(
        self,
        name: str,
    ) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(
                datetime.fromtimestamp(self.now - 3600, tz=timezone.utc)
            )
            .not_valid_after(
                datetime.fromtimestamp(
                    self.now + 7 * 24 * 60 * 60,
                    tz=timezone.utc,
                )
            )
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=1),
                critical=True,
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

    def make_leaf(
        self,
        *,
        issuer_key: rsa.RSAPrivateKey,
        issuer: x509.Certificate,
        eku: x509.ObjectIdentifier,
        common_name: str,
        dns_name: str | None = None,
    ) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        subject = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
        )
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(
                datetime.fromtimestamp(self.now - 60, tz=timezone.utc)
            )
            .not_valid_after(
                datetime.fromtimestamp(self.now + 7200, tz=timezone.utc)
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    issuer_key.public_key()
                ),
                critical=False,
            )
        )
        if dns_name is not None:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(dns_name)]),
                critical=False,
            )
        return key, builder.sign(issuer_key, hashes.SHA256())

    def make_crl(
        self,
        *,
        issuer_key: rsa.RSAPrivateKey,
        issuer: x509.Certificate,
    ) -> x509.CertificateRevocationList:
        return (
            x509.CertificateRevocationListBuilder()
            .issuer_name(issuer.subject)
            .last_update(
                datetime.fromtimestamp(self.now - 60, tz=timezone.utc)
            )
            .next_update(
                datetime.fromtimestamp(self.now + 3600, tz=timezone.utc)
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    issuer_key.public_key()
                ),
                critical=False,
            )
            .sign(issuer_key, hashes.SHA256())
        )

    def create_authority_receipts(self) -> dict[str, Path]:
        authority = InfrastructureObservationAuthority(
            self.database,
            expected_uid=0,
            clock=lambda: self.now,
        )

        def request(action: str, payload: dict) -> dict:
            return {
                "schema": "spectre.infrastructure.admin.v1",
                "request_id": str(uuid.uuid4()),
                "action": action,
                "payload": payload,
            }

        authority.administer(
            request(
                "cell.provision",
                {
                    "cell_id": self.cell_id,
                    "name": "SPECTRE fixture",
                    "region": "lab",
                    "classification_label": "test",
                },
            ),
            operator_uid=0,
        )
        host = authority.administer(
            request(
                "host.provision",
                {
                    "host_id": self.host_id,
                    "cell_id": self.cell_id,
                    "display_name": "Fixture Hyper-V",
                    "failure_domain_label": "single-host laboratory",
                    "approved_virtual_machines": [
                        {"vm_id": self.vm_id, "role": "ingress"}
                    ],
                },
            ),
            operator_uid=0,
        )
        agent = authority.administer(
            request(
                "agent.provision",
                {"agent_id": self.agent_id, "host_id": self.host_id},
            ),
            operator_uid=0,
        )
        certificate = authority.administer(
            request(
                "certificate.provision",
                {
                    "agent_id": self.agent_id,
                    "certificate_generation": 1,
                    "certificate_fingerprint_sha256": self.client_fingerprint,
                    "jws_key_id": f"spectre-hv:{self.agent_id}:g1",
                    "jws_algorithm": "PS256",
                    "jws_spki_der_base64": base64.b64encode(
                        self.jws_spki
                    ).decode("ascii"),
                    "jws_spki_sha256": self.jws_spki_sha256,
                    "valid_from_epoch": self.valid_from,
                    "valid_until_epoch": self.valid_until,
                },
            ),
            operator_uid=0,
        )
        ingress = BrokerPersistence(
            self.database,
            expected_uid=0,
        ).administer_infrastructure_ingress_access(
            {
                "schema": "spectre.infrastructure.ingress-access.v1",
                "request_id": str(uuid.uuid4()),
                "action": "ingress.replace",
                "payload": {
                    "service_account": "devcoord-infra-ingress",
                    "uid": self.ingress_uid,
                    "account_id": "spectre-infrastructure-ingress",
                    "valid_until_epoch": self.now + 7200,
                },
            },
            operator_uid=0,
            now_epoch=self.now,
        )
        reader = BrokerPersistence(
            self.database,
            expected_uid=0,
        ).administer_infrastructure_reader_access(
            {
                "schema": "spectre.infrastructure.reader-access.v1",
                "request_id": str(uuid.uuid4()),
                "action": "reader.replace",
                "payload": {
                    "service_account": "devcoord-console",
                    "uid": self.reader_uid,
                    "account_id": "spectre-console-infrastructure-reader",
                    "valid_until_epoch": self.now + 7200,
                },
            },
            operator_uid=0,
            now_epoch=self.now,
        )
        values = {
            "host": host,
            "agent": agent,
            "certificate": certificate,
            "ingress": ingress,
            "reader": reader,
        }
        paths: dict[str, Path] = {}
        for name, value in values.items():
            path = self.root / f"{name}-receipt.json"
            path.write_bytes(canonical_json(value).encode("utf-8"))
            path.chmod(0o600)
            paths[name] = path
        return paths

    def write_pki(self) -> None:
        self.server_chain_path = self.root / "server-fullchain.pem"
        self.server_key_path = self.root / "server-key.pem"
        self.client_ca_path = self.root / "client-ca.pem"
        self.client_crl_path = self.root / "client-ca.crl.pem"
        self.client_leaf_path = self.root / "client-leaf.pem"
        self.server_root_path = self.root / "server-root.pem"
        self.server_chain_path.write_bytes(
            self.server_leaf.public_bytes(serialization.Encoding.PEM)
            + self.server_ca.public_bytes(serialization.Encoding.PEM)
        )
        self.server_key_path.write_bytes(
            self.server_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self.client_ca_path.write_bytes(
            self.client_ca.public_bytes(serialization.Encoding.PEM)
        )
        self.client_crl_path.write_bytes(
            self.client_crl.public_bytes(serialization.Encoding.PEM)
        )
        self.client_leaf_path.write_bytes(
            self.client_leaf.public_bytes(serialization.Encoding.PEM)
        )
        self.server_root_path.write_bytes(
            self.server_ca.public_bytes(serialization.Encoding.PEM)
        )
        for path in (
            self.server_chain_path,
            self.server_key_path,
            self.client_ca_path,
            self.client_crl_path,
            self.client_leaf_path,
            self.server_root_path,
        ):
            path.chmod(0o600)

    def database_generation(self) -> str:
        with CoordinatorStore.open_read_only(
            self.database,
            expected_uid=0,
        ) as store:
            with store.read_transaction() as connection:
                return str(
                    connection.execute(
                        """
                        SELECT database_generation
                        FROM schema_metadata WHERE singleton = 1
                        """
                    ).fetchone()[0]
                )

    def write_config(self) -> Path:
        path = self.root / "ingress-config.json"
        value = {
            "schema": "spectre.infrastructure.ingress-config.v1",
            "listen": {
                "host": "0.0.0.0",
                "port": 9443,
                "public_host": "spectre.classified.guru:9443",
            },
            "tls": {
                "server_certificate_path": str(self.server_chain_path),
                "server_private_key_path": str(self.server_key_path),
                "server_certificate_generation": 1,
                "server_certificate_sha256": hashlib.sha256(
                    self.server_leaf.public_bytes(serialization.Encoding.DER)
                ).hexdigest(),
                "server_certificate_valid_from_epoch": int(
                    self.server_leaf.not_valid_before_utc.timestamp()
                ),
                "server_certificate_valid_until_epoch": int(
                    self.server_leaf.not_valid_after_utc.timestamp()
                ),
                "client_ca_certificate_path": str(self.client_ca_path),
                "client_crl_path": str(self.client_crl_path),
            },
            "artifact_root": str(self.root / "artifacts"),
            "broker": {
                "socket_path": str(self.socket_path),
                "expected_broker_uid": 0,
                "expected_socket_gid": os.getegid(),
                "expected_socket_mode": "0660",
                "authority_generation": self.authority_generation,
                "account_id": "spectre-infrastructure-ingress",
            },
            "limits": {
                "handshake_timeout_seconds": 5,
                "request_timeout_seconds": 10,
                "max_header_bytes": 16384,
                "max_body_bytes": 786432,
                "max_concurrency": 8,
                "rate_per_certificate_per_minute": 10,
                "rate_per_ip_per_minute": 20,
                "crl_max_age_seconds": 21600,
            },
        }
        path.write_bytes(canonical_json(value).encode("utf-8"))
        path.chmod(0o600)
        return path

    def inputs(self, *, output: Path | None = None) -> CentralReadinessInputs:
        return CentralReadinessInputs(
            database=self.database,
            host_provision_receipt=self.receipt_paths["host"],
            agent_provision_receipt=self.receipt_paths["agent"],
            certificate_provision_receipt=self.receipt_paths["certificate"],
            ingress_access_receipt=self.receipt_paths["ingress"],
            reader_access_receipt=self.receipt_paths["reader"],
            ingress_configuration=self.config_path,
            client_certificate=self.client_leaf_path,
            server_trust_root=self.server_root_path,
            output=output or self.output,
            validity_seconds=900,
        )

    def export(self, *, output: Path | None = None) -> dict:
        def account(name: str) -> SimpleNamespace:
            if name == "devcoord-infra-ingress":
                return SimpleNamespace(pw_uid=self.ingress_uid)
            if name == "devcoord-console":
                return SimpleNamespace(pw_uid=self.reader_uid)
            raise KeyError(name)

        versions = {
            "cryptography": "49.0.0",
            "cffi": "2.0.0",
            "pycparser": "2.22",
        }
        with (
            mock.patch(
                "devcoordinator.infrastructure_readiness.pwd.getpwnam",
                side_effect=account,
            ),
            mock.patch(
                "devcoordinator.infrastructure_ingress.importlib_metadata.version",
                side_effect=lambda package: versions[package],
            ),
        ):
            return export_observer_central_readiness(
                self.inputs(output=output),
                now_epoch=self.now,
                listener_probe=lambda host, port: self.assertEqual(
                    (host, port),
                    ("127.0.0.1", 9443),
                ),
            )

    def validate_enrollment_results(
        self,
        *,
        host_result: dict | None = None,
        agent_result: dict | None = None,
        certificate_result: dict | None = None,
    ) -> dict:
        defaults = {
            name: json.loads(path.read_text(encoding="utf-8"))["result"]
            for name, path in self.receipt_paths.items()
            if name in {"host", "agent", "certificate"}
        }
        with CoordinatorStore.open_read_only(
            self.database,
            expected_uid=0,
        ) as store:
            with store.read_transaction() as connection:
                return _validate_current_enrollment(
                    connection,
                    host_result=host_result or defaults["host"],
                    agent_result=agent_result or defaults["agent"],
                    certificate_result=(
                        certificate_result or defaults["certificate"]
                    ),
                )

    def test_exact_authority_and_pki_export_one_canonical_receipt(self) -> None:
        result = self.export()
        self.assertEqual(result["schema"], CENTRAL_READINESS_SCHEMA)
        raw = self.output.read_bytes()
        document = json.loads(raw)
        self.assertEqual(raw, canonical_json(document).encode("utf-8"))
        self.assertEqual(document["status"], "ready")
        self.assertEqual(document["cell_id"], self.cell_id)
        self.assertEqual(document["host_id"], self.host_id)
        self.assertEqual(document["agent_id"], self.agent_id)
        self.assertEqual(document["authority_generation"], self.authority_generation)
        self.assertEqual(
            document["client_certificate_sha256"],
            self.client_fingerprint,
        )
        self.assertEqual(
            document["jws_spki_sha256"],
            self.jws_spki_sha256,
        )
        self.assertEqual(
            document["ingress_server_certificate_sha256"],
            hashlib.sha256(
                self.server_leaf.public_bytes(serialization.Encoding.DER)
            ).hexdigest(),
        )
        self.assertEqual(
            document["ingress_server_certificate_generation"],
            1,
        )
        self.assertEqual(
            document["reader_access_receipt_sha256"],
            hashlib.sha256(
                self.receipt_paths["reader"].read_bytes()
            ).hexdigest(),
        )
        self.assertLessEqual(
            document["ingress_server_certificate_valid_until_epoch"]
            - document["ingress_server_certificate_valid_from_epoch"],
            7 * 24 * 60 * 60,
        )
        self.assertEqual(
            result["output_sha256"],
            hashlib.sha256(raw).hexdigest(),
        )
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def test_tampered_receipt_fails_before_output(self) -> None:
        document = json.loads(self.receipt_paths["host"].read_text())
        document["result"]["approved_vm_count"] = 2
        self.receipt_paths["host"].write_bytes(
            canonical_json(document).encode("utf-8")
        )
        with self.assertRaises(InfrastructureReadinessError):
            self.export()
        self.assertFalse(self.output.exists())

    def test_enrollment_rechecks_exact_windows_key_contract_and_spki(self) -> None:
        values = {
            name: json.loads(path.read_text(encoding="utf-8"))["result"]
            for name, path in self.receipt_paths.items()
            if name in {"host", "agent", "certificate"}
        }
        self.assertEqual(
            self.validate_enrollment_results()["jws_key_id"],
            f"spectre-hv:{self.agent_id}:g1",
        )

        wrong_key_id = dict(values["certificate"])
        wrong_key_id["jws_key_id"] = f"spectre-hv:{self.host_id}:g1"
        with self.assertRaises(InfrastructureReadinessError):
            self.validate_enrollment_results(
                certificate_result=wrong_key_id,
            )

        malformed_spki = dict(values["certificate"])
        malformed_spki["jws_spki_der_base64"] = base64.b64encode(
            b"not-a-canonical-rsa-spki"
        ).decode("ascii")
        malformed_spki["jws_spki_sha256"] = hashlib.sha256(
            b"not-a-canonical-rsa-spki"
        ).hexdigest()
        with self.assertRaises(InfrastructureReadinessError):
            self.validate_enrollment_results(
                certificate_result=malformed_spki,
            )

        bool_count = dict(values["host"])
        bool_count["approved_vm_count"] = True
        with self.assertRaises(InfrastructureReadinessError):
            self.validate_enrollment_results(host_result=bool_count)

    def test_changed_client_certificate_fails_before_output(self) -> None:
        _key, foreign = self.make_leaf(
            issuer_key=self.client_ca_key,
            issuer=self.client_ca,
            eku=ExtendedKeyUsageOID.CLIENT_AUTH,
            common_name="foreign observer",
        )
        self.client_leaf_path.write_bytes(
            foreign.public_bytes(serialization.Encoding.PEM)
        )
        self.client_leaf_path.chmod(0o600)
        with self.assertRaises(InfrastructureReadinessError):
            self.export()
        self.assertFalse(self.output.exists())

    def test_create_new_output_refuses_overwrite(self) -> None:
        self.output.write_text("retained", encoding="utf-8")
        self.output.chmod(0o600)
        with self.assertRaises(FileExistsError):
            self.export()
        self.assertEqual(self.output.read_text(encoding="utf-8"), "retained")

    def test_expired_or_wrong_ingress_grant_fails_before_output(self) -> None:
        with CoordinatorStore.open(self.database) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE broker_infrastructure_service_acl
                    SET enabled = 0
                    WHERE uid = ?
                      AND operation = 'infrastructure.ingest'
                    """,
                    (self.ingress_uid,),
                )
        with self.assertRaises(InfrastructureReadinessError):
            self.export()
        self.assertFalse(self.output.exists())

    def test_disabled_reader_grant_fails_before_output(self) -> None:
        with CoordinatorStore.open(self.database) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE broker_infrastructure_service_acl
                    SET enabled = 0
                    WHERE uid = ?
                      AND operation = 'infrastructure.read'
                    """,
                    (self.reader_uid,),
                )
        with self.assertRaises(InfrastructureReadinessError):
            self.export()
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
