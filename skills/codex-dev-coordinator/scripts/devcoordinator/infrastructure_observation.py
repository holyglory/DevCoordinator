"""Broker-owned remote-infrastructure observation authority.

This module deliberately starts after transport verification.  A separately
supervised ingress is responsible for TLS/JWS parsing and supplies only the
closed :class:`VerifiedTransportEvidence` fields below.  The Coordinator still
cryptographically reverifies the retained PS256 envelope and rechecks the exact
enrolled certificate generation, signing-key binding, agent/host/cell scope,
payload digest, replay state, and current roster in one SQLite transaction.

No caller can provide SQL, filesystem paths, commands, or mutable host actions.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import time
from typing import Any, Callable, Mapping
import unicodedata
import uuid

from .schema import (
    INFRASTRUCTURE_CERTIFICATE_MAX_OVERLAP_SECONDS,
    INFRASTRUCTURE_CERTIFICATE_MAX_VALIDITY_SECONDS,
)
from .infrastructure_artifacts import (
    InfrastructureArtifactError,
    SYSTEM_BROKER_ARTIFACT_ROOT,
    SYSTEM_INGRESS_STAGING_ROOT,
    SignedEnvelopeArtifact,
    publish_verified_staged_signed_envelope,
    read_staged_signed_envelope,
)
from .store import CoordinatorStore, canonical_json, utc_timestamp


INFRASTRUCTURE_SCHEMA = "spectre.infrastructure.observation.v1"
INFRASTRUCTURE_BROKER_PROJECT_ID = "infrastructure"
INFRASTRUCTURE_INGEST_RESOURCE_ID = "observation-ingest"
INFRASTRUCTURE_READ_RESOURCE_ID = "observation-read"
INFRASTRUCTURE_VERIFICATION_CONTEXT_RESOURCE_ID = "verification-context"
INFRASTRUCTURE_ADMIN_SCHEMA = "spectre.infrastructure.admin.v1"
INFRASTRUCTURE_VERIFICATION_CONTEXT_SCHEMA = (
    "spectre.infrastructure.verification-context.v1"
)
INFRASTRUCTURE_JWS_ALGORITHM = "PS256"
INFRASTRUCTURE_JWS_TYPE = "SPECTRE-INFRASTRUCTURE-OBSERVATION+JWS"

MAX_OBSERVATION_BYTES = 512 * 1024
MAX_OUTER_INGEST_BYTES = 2 * 1024 * 1024
MAX_VIRTUAL_MACHINES = 1024
MAX_MANAGEMENT_ADDRESSES = 16
MAX_VM_ADDRESSES = 32
MAX_FUTURE_SKEW_SECONDS = 300
MAX_HOST_PAGE = 100
MAX_VM_PAGE_PER_HOST = 256
MAX_REJECTION_PAGE_PER_HOST = 20
MAX_PROJECTION_BYTES = 12 * 1024 * 1024
MAX_SQLITE_INTEGER = (1 << 63) - 1
OBSERVATION_CADENCE_SECONDS = 60
OBSERVATION_STALE_AFTER_SECONDS = 180

_HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
_SEMVER = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]{1,48})?(?:\+[0-9A-Za-z.-]{1,48})?"
)
_ROLE = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
_ERROR_CODE = re.compile(r"[a-z][a-z0-9_.-]{0,63}")


class InfrastructureObservationError(RuntimeError):
    """Base error for the remote-infrastructure authority."""


class InfrastructureValidationError(InfrastructureObservationError):
    """A safe, typed report rejection."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class InfrastructureIngestRejected(InfrastructureValidationError):
    """A rejection already committed to the immutable ingest audit."""


@dataclass(frozen=True)
class VerifiedTransportEvidence:
    """Closed evidence asserted by the separately enrolled local ingress.

    ``mtls_verified`` is an aggregate contract, not a substitute for TLS
    validation in this module. The future ingress may set it only after
    fail-closed private-CA chain, client-auth EKU, leaf validity, current
    revocation, and exact leaf-fingerprint checks for the request.
    """

    mtls_verified: bool
    jws_verified: bool
    certificate_fingerprint_sha256: str
    certificate_generation: int
    jws_key_id: str
    jws_algorithm: str
    jws_spki_sha256: str
    canonical_payload_sha256: str

    @classmethod
    def from_value(cls, value: Any) -> "VerifiedTransportEvidence":
        _require_exact_fields(
            value,
            {
                "mtls_verified",
                "jws_verified",
                "certificate_fingerprint_sha256",
                "certificate_generation",
                "jws_key_id",
                "jws_algorithm",
                "jws_spki_sha256",
                "canonical_payload_sha256",
            },
            code="invalid_transport_evidence",
            subject="transport evidence",
        )
        fingerprint = _sha256(
            value["certificate_fingerprint_sha256"],
            "certificate_fingerprint_sha256",
            code="invalid_transport_evidence",
        )
        generation = _integer(
            value["certificate_generation"],
            "certificate_generation",
            minimum=1,
            maximum=2_147_483_647,
            code="invalid_transport_evidence",
        )
        key_id = _bounded_string(
            value["jws_key_id"],
            "jws_key_id",
            minimum=1,
            maximum=128,
            code="invalid_transport_evidence",
        )
        algorithm = _bounded_string(
            value["jws_algorithm"],
            "jws_algorithm",
            minimum=1,
            maximum=16,
            code="invalid_transport_evidence",
        )
        if algorithm != INFRASTRUCTURE_JWS_ALGORITHM:
            raise InfrastructureValidationError(
                "invalid_transport_evidence",
                "jws_algorithm must be the exact allowed PS256 algorithm.",
            )
        spki_sha256 = _sha256(
            value["jws_spki_sha256"],
            "jws_spki_sha256",
            code="invalid_transport_evidence",
        )
        payload_sha256 = _sha256(
            value["canonical_payload_sha256"],
            "canonical_payload_sha256",
            code="invalid_transport_evidence",
        )
        if type(value["mtls_verified"]) is not bool:
            raise InfrastructureValidationError(
                "invalid_transport_evidence",
                "mtls_verified must be a boolean.",
            )
        if type(value["jws_verified"]) is not bool:
            raise InfrastructureValidationError(
                "invalid_transport_evidence",
                "jws_verified must be a boolean.",
            )
        return cls(
            mtls_verified=value["mtls_verified"],
            jws_verified=value["jws_verified"],
            certificate_fingerprint_sha256=fingerprint,
            certificate_generation=generation,
            jws_key_id=key_id,
            jws_algorithm=algorithm,
            jws_spki_sha256=spki_sha256,
            canonical_payload_sha256=payload_sha256,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "mtls_verified": self.mtls_verified,
            "jws_verified": self.jws_verified,
            "certificate_fingerprint_sha256": (
                self.certificate_fingerprint_sha256
            ),
            "certificate_generation": self.certificate_generation,
            "jws_key_id": self.jws_key_id,
            "jws_algorithm": self.jws_algorithm,
            "jws_spki_sha256": self.jws_spki_sha256,
            "canonical_payload_sha256": self.canonical_payload_sha256,
        }


def parse_canonical_observation_payload(
    payload: bytes, *, maximum_bytes: int = MAX_OBSERVATION_BYTES
) -> tuple[dict[str, Any], str]:
    """Parse only exact canonical UTF-8 JSON bytes for a verified JWS payload.

    The ingress calls this *after* JWS verification. Duplicate keys, floats,
    non-finite numbers, non-NFC strings, escaped/alternate Unicode spellings,
    whitespace, and non-sorted object keys are rejected because the supplied
    bytes must equal the Coordinator's one canonical serialization exactly.
    """

    if not isinstance(payload, bytes):
        raise InfrastructureValidationError(
            "invalid_canonical_payload", "JWS payload must be raw bytes."
        )
    if (
        type(maximum_bytes) is not int
        or maximum_bytes < 1
        or maximum_bytes > MAX_OUTER_INGEST_BYTES
    ):
        raise ValueError("canonical payload maximum_bytes is invalid")
    if not payload or len(payload) > maximum_bytes:
        raise InfrastructureValidationError(
            "observation_oversized",
            "JWS payload is empty or exceeds the v1 payload byte bound.",
        )

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise InfrastructureValidationError(
                    "duplicate_json_key",
                    "JWS payload contains a duplicate JSON object key.",
                )
            result[key] = value
        return result

    def reject_float(_value: str) -> Any:
        raise InfrastructureValidationError(
            "json_float_not_allowed",
            "JWS payload floats are outside the closed v1 contract.",
        )

    def reject_constant(_value: str) -> Any:
        raise InfrastructureValidationError(
            "json_constant_not_allowed",
            "JWS payload non-finite numbers are outside the JSON contract.",
        )

    try:
        text = payload.decode("utf-8", errors="strict")
        decoded = json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_float=reject_float,
            parse_constant=reject_constant,
        )
    except UnicodeDecodeError as error:
        raise InfrastructureValidationError(
            "invalid_canonical_payload", "JWS payload is not strict UTF-8."
        ) from error
    except json.JSONDecodeError as error:
        raise InfrastructureValidationError(
            "invalid_canonical_payload", "JWS payload is not valid JSON."
        ) from error
    if not isinstance(decoded, dict):
        raise InfrastructureValidationError(
            "invalid_canonical_payload", "JWS payload must be a JSON object."
        )
    _require_nfc_json_strings(decoded)
    canonical = canonical_json(decoded).encode("utf-8")
    if canonical != payload:
        raise InfrastructureValidationError(
            "noncanonical_json_payload",
            "JWS payload bytes do not equal the canonical v1 JSON serialization.",
        )
    return decoded, hashlib.sha256(canonical).hexdigest()


def prepare_ingest_arguments(value: Any) -> dict[str, Any]:
    """Apply the broker's outer bound without consuming core rejection audit.

    Strict payload/schema validation remains in :meth:`ingest`, after the
    authenticated service principal and certificate can be associated with an
    immutable rejection event.
    """

    _require_exact_fields(
        value,
        {"transport", "observation", "artifact"},
        code="invalid_arguments",
        subject="infrastructure ingest arguments",
    )
    transport = VerifiedTransportEvidence.from_value(value["transport"])
    if not isinstance(value["observation"], dict):
        raise InfrastructureValidationError(
            "invalid_arguments",
            "observation must be a JSON object.",
        )
    try:
        artifact = SignedEnvelopeArtifact.from_value(value["artifact"])
    except InfrastructureArtifactError as error:
        raise InfrastructureValidationError(
            "invalid_artifact_evidence", str(error)
        ) from None
    detached = {
        "transport": transport.to_dict(),
        "observation": _detached_json(value["observation"], code="invalid_arguments"),
        "artifact": artifact.to_dict(),
    }
    if _encoded_size(detached, code="invalid_arguments") > MAX_OUTER_INGEST_BYTES:
        raise InfrastructureValidationError(
            "invalid_arguments",
            "Infrastructure ingest envelope exceeds the broker outer bound.",
        )
    return detached


def prepare_read_arguments(value: Any) -> dict[str, Any]:
    """Normalize a bounded immutable-ID pagination request."""

    if not isinstance(value, Mapping):
        raise InfrastructureValidationError(
            "invalid_arguments",
            "Infrastructure read arguments must be a JSON object.",
        )
    allowed = {
        "after_host_id",
        "host_limit",
        "vm_limit_per_host",
        "rejection_limit_per_host",
    }
    unexpected = sorted(set(value) - allowed)
    if unexpected:
        raise InfrastructureValidationError(
            "invalid_arguments",
            "Infrastructure read arguments contain unsupported fields.",
        )
    after_host_id = value.get("after_host_id")
    if after_host_id is not None:
        after_host_id = _canonical_uuid(
            after_host_id, "after_host_id", code="invalid_arguments"
        )
    return {
        "after_host_id": after_host_id,
        "host_limit": _integer(
            value.get("host_limit", 50),
            "host_limit",
            minimum=1,
            maximum=MAX_HOST_PAGE,
            code="invalid_arguments",
        ),
        "vm_limit_per_host": _integer(
            value.get("vm_limit_per_host", 128),
            "vm_limit_per_host",
            minimum=0,
            maximum=MAX_VM_PAGE_PER_HOST,
            code="invalid_arguments",
        ),
        "rejection_limit_per_host": _integer(
            value.get("rejection_limit_per_host", 1),
            "rejection_limit_per_host",
            minimum=0,
            maximum=MAX_REJECTION_PAGE_PER_HOST,
            code="invalid_arguments",
        ),
    }


def prepare_verification_context_arguments(value: Any) -> dict[str, Any]:
    """Normalize one exact, non-enumerating ingress key lookup."""

    _require_exact_fields(
        value,
        {
            "certificate_fingerprint_sha256",
            "certificate_generation",
        },
        code="invalid_arguments",
        subject="infrastructure verification-context arguments",
    )
    return {
        "certificate_fingerprint_sha256": _sha256(
            value["certificate_fingerprint_sha256"],
            "certificate_fingerprint_sha256",
            code="invalid_arguments",
        ),
        "certificate_generation": _integer(
            value["certificate_generation"],
            "certificate_generation",
            minimum=1,
            maximum=2_147_483_647,
            code="invalid_arguments",
        ),
    }


def _der_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("DER length is truncated")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    width = first & 0x7F
    if width == 0 or width > 4 or offset + width > len(data):
        raise ValueError("DER length is invalid")
    encoded = data[offset : offset + width]
    if encoded[0] == 0:
        raise ValueError("DER length is not minimally encoded")
    length = int.from_bytes(encoded, "big")
    if length < 0x80:
        raise ValueError("DER long length is not minimally encoded")
    return length, offset + width


def _der_tlv(
    data: bytes, offset: int, expected_tag: int
) -> tuple[bytes, int]:
    if offset >= len(data) or data[offset] != expected_tag:
        raise ValueError("DER tag does not match the PS256 SPKI contract")
    length, content_offset = _der_length(data, offset + 1)
    end = content_offset + length
    if end > len(data):
        raise ValueError("DER value is truncated")
    return data[content_offset:end], end


def _der_encode_length(length: int) -> bytes:
    if length < 0:
        raise ValueError("DER length cannot be negative")
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _der_encode_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_encode_length(len(content)) + content


def _der_positive_integer(content: bytes, field: str) -> int:
    if not content:
        raise ValueError(f"DER {field} integer is empty")
    if content[0] & 0x80:
        raise ValueError(f"DER {field} integer is negative")
    if len(content) > 1 and content[0] == 0 and not (content[1] & 0x80):
        raise ValueError(f"DER {field} integer is not minimally encoded")
    return int.from_bytes(content, "big")


def _der_encode_positive_integer(value: int) -> bytes:
    encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return _der_encode_tlv(0x02, encoded)


def normalize_ps256_spki(
    spki_der_base64: Any,
    supplied_sha256: Any,
    *,
    code: str,
) -> dict[str, Any]:
    """Validate and canonicalize an RSA SubjectPublicKeyInfo for JWS PS256.

    Only canonical DER ``rsaEncryption`` SPKI with a 3072–8192-bit modulus and
    public exponent exactly 65537 is accepted. The function
    reconstructs the complete SPKI and requires byte-for-byte equality so an
    arbitrary base64 blob can never be enrolled as verification material.
    """

    encoded = _bounded_string(
        spki_der_base64,
        "jws_spki_der_base64",
        minimum=1,
        maximum=4096,
        code=code,
    )
    digest = _sha256(
        supplied_sha256,
        "jws_spki_sha256",
        code=code,
    )
    try:
        der = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise InfrastructureValidationError(
            code,
            "jws_spki_der_base64 must be canonical unwrapped base64.",
        ) from error
    if base64.b64encode(der).decode("ascii") != encoded:
        raise InfrastructureValidationError(
            code,
            "jws_spki_der_base64 must use the canonical base64 spelling.",
        )
    try:
        outer, outer_end = _der_tlv(der, 0, 0x30)
        if outer_end != len(der):
            raise ValueError("DER SPKI has trailing bytes")
        algorithm, algorithm_end = _der_tlv(outer, 0, 0x30)
        if algorithm_end >= len(outer):
            raise ValueError("DER SPKI omits the subject public key")
        # rsaEncryption OBJECT IDENTIFIER plus explicit NULL parameters.
        if algorithm != bytes.fromhex("06092a864886f70d0101010500"):
            raise ValueError("DER SPKI algorithm is not canonical rsaEncryption")
        bit_string, bit_string_end = _der_tlv(outer, algorithm_end, 0x03)
        if bit_string_end != len(outer) or not bit_string or bit_string[0] != 0:
            raise ValueError("DER SPKI bit string is not canonical")
        rsa_public_key = bit_string[1:]
        rsa_sequence, rsa_end = _der_tlv(rsa_public_key, 0, 0x30)
        if rsa_end != len(rsa_public_key):
            raise ValueError("DER RSA public key has trailing bytes")
        modulus_bytes, integer_offset = _der_tlv(rsa_sequence, 0, 0x02)
        exponent_bytes, integer_end = _der_tlv(
            rsa_sequence, integer_offset, 0x02
        )
        if integer_end != len(rsa_sequence):
            raise ValueError("DER RSA public key has extra fields")
        modulus = _der_positive_integer(modulus_bytes, "modulus")
        exponent = _der_positive_integer(exponent_bytes, "exponent")
        if not 3072 <= modulus.bit_length() <= 8192:
            raise ValueError("RSA modulus must be 3072 through 8192 bits")
        if modulus % 2 == 0:
            raise ValueError("RSA modulus must be odd")
        if exponent != 65_537:
            raise ValueError("RSA public exponent must be exactly 65537")

        canonical_rsa = _der_encode_tlv(
            0x30,
            _der_encode_positive_integer(modulus)
            + _der_encode_positive_integer(exponent),
        )
        canonical_algorithm = _der_encode_tlv(
            0x30, bytes.fromhex("06092a864886f70d0101010500")
        )
        canonical_der = _der_encode_tlv(
            0x30,
            canonical_algorithm + _der_encode_tlv(0x03, b"\x00" + canonical_rsa),
        )
        if canonical_der != der:
            raise ValueError("DER SPKI does not round-trip canonically")
    except ValueError as error:
        raise InfrastructureValidationError(
            code,
            f"jws_spki_der_base64 is not a canonical PS256 RSA SPKI: {error}.",
        ) from error
    calculated = hashlib.sha256(der).hexdigest()
    if calculated != digest:
        raise InfrastructureValidationError(
            code,
            "jws_spki_sha256 does not match the canonical DER SPKI bytes.",
        )
    return {
        "jws_algorithm": INFRASTRUCTURE_JWS_ALGORITHM,
        "jws_spki_der_base64": encoded,
        "jws_spki_sha256": calculated,
        "rsa_modulus_bits": modulus.bit_length(),
        "rsa_public_exponent": exponent,
    }


def _validate_certificate_validity_window(
    valid_from_epoch: int,
    valid_until_epoch: int,
    *,
    code: str,
) -> None:
    if valid_until_epoch <= valid_from_epoch:
        raise InfrastructureValidationError(
            code,
            "certificate validity window must be increasing.",
        )
    if (
        valid_until_epoch - valid_from_epoch
        > INFRASTRUCTURE_CERTIFICATE_MAX_VALIDITY_SECONDS
    ):
        raise InfrastructureValidationError(
            code,
            "certificate validity window must not exceed 30 days.",
        )


def _require_certificate_overlap_bound(
    connection: sqlite3.Connection,
    *,
    agent_id: str,
    valid_from_epoch: int,
    valid_until_epoch: int,
) -> None:
    overlapping = connection.execute(
        """
        SELECT certificate_generation
        FROM infrastructure_agent_certificates
        WHERE agent_id = ?
          AND revoked_at IS NULL
          AND MIN(valid_until_epoch, ?)
              - MAX(valid_from_epoch, ?) > ?
        LIMIT 1
        """,
        (
            agent_id,
            valid_until_epoch,
            valid_from_epoch,
            INFRASTRUCTURE_CERTIFICATE_MAX_OVERLAP_SECONDS,
        ),
    ).fetchone()
    if overlapping is not None:
        raise InfrastructureObservationError(
            "new certificate generation would overlap an unrevoked "
            "generation by more than 72 hours"
        )


def infrastructure_scope_sha256(
    host_id: str, approved_virtual_machines: Mapping[str, str | None]
) -> str:
    """Return the exact centrally assigned host/VM/role scope digest."""

    canonical_host = _canonical_uuid(host_id, "host_id", code="invalid_enrollment")
    if not isinstance(approved_virtual_machines, Mapping):
        raise InfrastructureValidationError(
            "invalid_enrollment",
            "approved_virtual_machines must be an immutable-ID mapping.",
        )
    if len(approved_virtual_machines) > MAX_VIRTUAL_MACHINES:
        raise InfrastructureValidationError(
            "invalid_enrollment",
            "approved_virtual_machines exceeds the v1 host bound.",
        )
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_vm_id, raw_role in approved_virtual_machines.items():
        vm_id = _canonical_uuid(raw_vm_id, "vm_id", code="invalid_enrollment")
        if vm_id in seen:
            raise InfrastructureValidationError(
                "invalid_enrollment", "approved VM identities must be unique."
            )
        seen.add(vm_id)
        role = _role(raw_role, code="invalid_enrollment")
        normalized.append({"vm_id": vm_id, "role": role})
    material = {
        "schema": "spectre.infrastructure.scope.v1",
        "host_id": canonical_host,
        "virtual_machines": sorted(normalized, key=lambda item: item["vm_id"]),
    }
    return hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()


def prepare_infrastructure_admin_request(value: Any) -> dict[str, Any]:
    """Normalize the complete root-only v1 administration request."""

    _require_exact_fields(
        value,
        {"schema", "request_id", "action", "payload"},
        code="invalid_admin_request",
        subject="infrastructure admin request",
    )
    if value["schema"] != INFRASTRUCTURE_ADMIN_SCHEMA:
        raise InfrastructureValidationError(
            "invalid_admin_request",
            "Infrastructure admin request schema is unsupported.",
        )
    request_id = _canonical_uuid(
        value["request_id"],
        "request_id",
        code="invalid_admin_request",
    )
    action = _bounded_string(
        value["action"],
        "action",
        minimum=1,
        maximum=64,
        code="invalid_admin_request",
    )
    payload = value["payload"]
    if action == "cell.provision":
        _require_exact_fields(
            payload,
            {"cell_id", "name", "region", "classification_label"},
            code="invalid_admin_request",
            subject="cell provision payload",
        )
        normalized_payload: dict[str, Any] = {
            "cell_id": _canonical_uuid(
                payload["cell_id"], "cell_id", code="invalid_admin_request"
            ),
            "name": _bounded_string(
                payload["name"],
                "name",
                minimum=1,
                maximum=128,
                code="invalid_admin_request",
            ),
            "region": _optional_bounded_string(
                payload["region"],
                "region",
                maximum=128,
                code="invalid_admin_request",
            ),
            "classification_label": _optional_bounded_string(
                payload["classification_label"],
                "classification_label",
                maximum=128,
                code="invalid_admin_request",
            ),
        }
    elif action == "host.provision":
        _require_exact_fields(
            payload,
            {
                "host_id",
                "cell_id",
                "display_name",
                "failure_domain_label",
                "approved_virtual_machines",
            },
            code="invalid_admin_request",
            subject="host provision payload",
        )
        raw_scope = payload["approved_virtual_machines"]
        if not isinstance(raw_scope, list) or len(raw_scope) > MAX_VIRTUAL_MACHINES:
            raise InfrastructureValidationError(
                "invalid_admin_request",
                "approved_virtual_machines must be a bounded array.",
            )
        scope: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in raw_scope:
            _require_exact_fields(
                item,
                {"vm_id", "role"},
                code="invalid_admin_request",
                subject="approved virtual machine",
            )
            vm_id = _canonical_uuid(
                item["vm_id"], "vm_id", code="invalid_admin_request"
            )
            if vm_id in seen:
                raise InfrastructureValidationError(
                    "invalid_admin_request",
                    "approved virtual machine identities must be unique.",
                )
            seen.add(vm_id)
            scope.append(
                {
                    "vm_id": vm_id,
                    "role": _role(item["role"], code="invalid_admin_request"),
                }
            )
        normalized_payload = {
            "host_id": _canonical_uuid(
                payload["host_id"], "host_id", code="invalid_admin_request"
            ),
            "cell_id": _canonical_uuid(
                payload["cell_id"], "cell_id", code="invalid_admin_request"
            ),
            "display_name": _bounded_string(
                payload["display_name"],
                "display_name",
                minimum=1,
                maximum=128,
                code="invalid_admin_request",
            ),
            "failure_domain_label": _bounded_string(
                payload["failure_domain_label"],
                "failure_domain_label",
                minimum=1,
                maximum=256,
                code="invalid_admin_request",
            ),
            "approved_virtual_machines": sorted(
                scope, key=lambda item: item["vm_id"]
            ),
        }
    elif action == "agent.provision":
        _require_exact_fields(
            payload,
            {"agent_id", "host_id"},
            code="invalid_admin_request",
            subject="agent provision payload",
        )
        normalized_payload = {
            "agent_id": _canonical_uuid(
                payload["agent_id"], "agent_id", code="invalid_admin_request"
            ),
            "host_id": _canonical_uuid(
                payload["host_id"], "host_id", code="invalid_admin_request"
            ),
        }
    elif action == "certificate.provision":
        _require_exact_fields(
            payload,
            {
                "agent_id",
                "certificate_generation",
                "certificate_fingerprint_sha256",
                "jws_key_id",
                "jws_algorithm",
                "jws_spki_der_base64",
                "jws_spki_sha256",
                "valid_from_epoch",
                "valid_until_epoch",
            },
            code="invalid_admin_request",
            subject="certificate provision payload",
        )
        algorithm = _bounded_string(
            payload["jws_algorithm"],
            "jws_algorithm",
            minimum=1,
            maximum=16,
            code="invalid_admin_request",
        )
        if algorithm != INFRASTRUCTURE_JWS_ALGORITHM:
            raise InfrastructureValidationError(
                "invalid_admin_request",
                "jws_algorithm must be the exact allowed PS256 algorithm.",
            )
        signing_material = normalize_ps256_spki(
            payload["jws_spki_der_base64"],
            payload["jws_spki_sha256"],
            code="invalid_admin_request",
        )
        valid_from = _integer(
            payload["valid_from_epoch"],
            "valid_from_epoch",
            minimum=0,
            maximum=MAX_SQLITE_INTEGER,
            code="invalid_admin_request",
        )
        valid_until = _integer(
            payload["valid_until_epoch"],
            "valid_until_epoch",
            minimum=1,
            maximum=MAX_SQLITE_INTEGER,
            code="invalid_admin_request",
        )
        _validate_certificate_validity_window(
            valid_from,
            valid_until,
            code="invalid_admin_request",
        )
        normalized_payload = {
            "agent_id": _canonical_uuid(
                payload["agent_id"], "agent_id", code="invalid_admin_request"
            ),
            "certificate_generation": _integer(
                payload["certificate_generation"],
                "certificate_generation",
                minimum=1,
                maximum=2_147_483_647,
                code="invalid_admin_request",
            ),
            "certificate_fingerprint_sha256": _sha256(
                payload["certificate_fingerprint_sha256"],
                "certificate_fingerprint_sha256",
                code="invalid_admin_request",
            ),
            "jws_key_id": _bounded_string(
                payload["jws_key_id"],
                "jws_key_id",
                minimum=1,
                maximum=128,
                code="invalid_admin_request",
            ),
            "jws_algorithm": algorithm,
            "jws_spki_der_base64": signing_material["jws_spki_der_base64"],
            "jws_spki_sha256": signing_material["jws_spki_sha256"],
            "valid_from_epoch": valid_from,
            "valid_until_epoch": valid_until,
        }
    elif action == "certificate.revoke":
        _require_exact_fields(
            payload,
            {"agent_id", "certificate_generation", "reason"},
            code="invalid_admin_request",
            subject="certificate revoke payload",
        )
        normalized_payload = {
            "agent_id": _canonical_uuid(
                payload["agent_id"], "agent_id", code="invalid_admin_request"
            ),
            "certificate_generation": _integer(
                payload["certificate_generation"],
                "certificate_generation",
                minimum=1,
                maximum=2_147_483_647,
                code="invalid_admin_request",
            ),
            "reason": _bounded_string(
                payload["reason"],
                "reason",
                minimum=1,
                maximum=256,
                code="invalid_admin_request",
            ),
        }
    else:
        raise InfrastructureValidationError(
            "invalid_admin_request",
            "Infrastructure admin action is unsupported.",
        )
    return {
        "schema": INFRASTRUCTURE_ADMIN_SCHEMA,
        "request_id": request_id,
        "action": action,
        "payload": normalized_payload,
    }


class InfrastructureObservationAuthority:
    """Atomic enrollment, ingest, replay, audit, and bounded read projection."""

    def __init__(
        self,
        database_path: str | os.PathLike[str],
        *,
        expected_uid: int | None = None,
        busy_timeout_ms: int = 5_000,
        clock: Callable[[], float] = time.time,
        ingress_staging_root: str | os.PathLike[str] = (
            SYSTEM_INGRESS_STAGING_ROOT
        ),
        broker_artifact_root: str | os.PathLike[str] = (
            SYSTEM_BROKER_ARTIFACT_ROOT
        ),
    ) -> None:
        self.database_path = Path(database_path)
        self.expected_uid = os.geteuid() if expected_uid is None else int(expected_uid)
        self.busy_timeout_ms = int(busy_timeout_ms)
        self._clock = clock
        self.ingress_staging_root = Path(ingress_staging_root)
        self.broker_artifact_root = Path(broker_artifact_root)

    def administer(
        self,
        request: Mapping[str, Any],
        *,
        operator_uid: int,
    ) -> dict[str, Any]:
        """Apply one root-owned closed request with an immutable atomic receipt."""

        if type(operator_uid) is not int or operator_uid != 0:
            raise PermissionError(
                "infrastructure administration requires the root service owner"
            )
        if self.expected_uid != 0:
            raise PermissionError(
                "infrastructure administration requires a root-owned authority"
            )
        normalized = prepare_infrastructure_admin_request(request)
        request_json = canonical_json(normalized)
        request_sha256 = hashlib.sha256(request_json.encode("utf-8")).hexdigest()
        request_id = str(normalized["request_id"])
        now = utc_timestamp(self._clock())
        replayed = False
        result: dict[str, Any]
        result_sha256: str
        created_at: str
        with self._store() as store:
            with store.immediate_transaction(
                revision_kind=None, check_invariants=False
            ) as connection:
                existing = connection.execute(
                    """
                    SELECT request_schema, action, request_json, request_sha256,
                           result_json, result_sha256, operator_uid,
                           authority_schema_version, created_at
                    FROM infrastructure_admin_receipts
                    WHERE request_id = ?
                    """,
                    (request_id,),
                ).fetchone()
                if existing is not None:
                    if (
                        str(existing["request_schema"])
                        != INFRASTRUCTURE_ADMIN_SCHEMA
                        or str(existing["action"]) != normalized["action"]
                        or str(existing["request_json"]) != request_json
                        or str(existing["request_sha256"]) != request_sha256
                        or int(existing["operator_uid"]) != operator_uid
                        or int(existing["authority_schema_version"]) != 14
                    ):
                        raise InfrastructureObservationError(
                            "admin_request_conflict: request_id already binds a "
                            "different immutable administration request"
                        )
                    result_json = str(existing["result_json"])
                    result_sha256 = str(existing["result_sha256"])
                    if (
                        hashlib.sha256(result_json.encode("utf-8")).hexdigest()
                        != result_sha256
                    ):
                        raise InfrastructureObservationError(
                            "retained infrastructure admin receipt result is corrupt"
                        )
                    decoded = json.loads(result_json)
                    if not isinstance(decoded, dict):
                        raise InfrastructureObservationError(
                            "retained infrastructure admin receipt result is invalid"
                        )
                    result = decoded
                    created_at = str(existing["created_at"])
                    replayed = True
                else:
                    result = self._apply_admin_action(
                        connection,
                        action=str(normalized["action"]),
                        payload=normalized["payload"],
                        now=now,
                    )
                    result_json = canonical_json(result)
                    result_sha256 = hashlib.sha256(
                        result_json.encode("utf-8")
                    ).hexdigest()
                    connection.execute(
                        """
                        INSERT INTO infrastructure_admin_receipts(
                            request_id, request_schema, action,
                            request_json, request_sha256,
                            result_json, result_sha256,
                            operator_uid, authority_schema_version, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 14, ?)
                        """,
                        (
                            request_id,
                            INFRASTRUCTURE_ADMIN_SCHEMA,
                            normalized["action"],
                            request_json,
                            request_sha256,
                            result_json,
                            result_sha256,
                            operator_uid,
                            now,
                        ),
                    )
                    connection.execute(
                        """
                        UPDATE schema_metadata
                        SET state_revision = state_revision + 1, updated_at = ?
                        WHERE singleton = 1
                        """,
                        (now,),
                    )
                    created_at = now
        return {
            "receipt_schema": "spectre.infrastructure.admin-receipt.v1",
            "request_id": request_id,
            "request_schema": INFRASTRUCTURE_ADMIN_SCHEMA,
            "action": normalized["action"],
            "request_sha256": request_sha256,
            "result_sha256": result_sha256,
            "operator_uid": operator_uid,
            "authority_schema_version": 14,
            "created_at": created_at,
            "replayed": replayed,
            "result": result,
        }

    @staticmethod
    def _apply_admin_action(
        connection: sqlite3.Connection,
        *,
        action: str,
        payload: Mapping[str, Any],
        now: str,
    ) -> dict[str, Any]:
        if action == "cell.provision":
            existing = connection.execute(
                """
                SELECT name, region, classification_label, enabled
                FROM infrastructure_cells WHERE cell_id = ?
                """,
                (payload["cell_id"],),
            ).fetchone()
            expected = (
                payload["name"],
                payload["region"],
                payload["classification_label"],
            )
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO infrastructure_cells(
                        cell_id, name, region, classification_label,
                        enabled, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 1, ?, ?)
                    """,
                    (
                        payload["cell_id"],
                        *expected,
                        now,
                        now,
                    ),
                )
            elif (
                str(existing["name"]) != expected[0]
                or existing["region"] != expected[1]
                or existing["classification_label"] != expected[2]
                or not bool(existing["enabled"])
            ):
                raise InfrastructureObservationError(
                    "cell identity already exists with a different enrollment"
                )
            return {
                "cell_id": payload["cell_id"],
                "name": payload["name"],
                "region": payload["region"],
                "classification_label": payload["classification_label"],
            }

        if action == "host.provision":
            if connection.execute(
                """
                SELECT 1 FROM infrastructure_cells
                WHERE cell_id = ? AND enabled = 1
                """,
                (payload["cell_id"],),
            ).fetchone() is None:
                raise InfrastructureObservationError(
                    "host enrollment requires an enabled existing cell"
                )
            scope = list(payload["approved_virtual_machines"])
            scope_sha256 = infrastructure_scope_sha256(
                str(payload["host_id"]),
                {item["vm_id"]: item["role"] for item in scope},
            )
            existing = connection.execute(
                """
                SELECT cell_id, display_name, failure_domain_label,
                       platform, scope_sha256, enabled
                FROM infrastructure_hosts WHERE host_id = ?
                """,
                (payload["host_id"],),
            ).fetchone()
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO infrastructure_hosts(
                        host_id, cell_id, display_name, failure_domain_label,
                        platform, scope_sha256, enabled, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 'windows-hyperv', ?, 1, ?, ?)
                    """,
                    (
                        payload["host_id"],
                        payload["cell_id"],
                        payload["display_name"],
                        payload["failure_domain_label"],
                        scope_sha256,
                        now,
                        now,
                    ),
                )
                connection.executemany(
                    """
                    INSERT INTO infrastructure_host_vm_scope(
                        host_id, vm_id, approved_role, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            payload["host_id"],
                            item["vm_id"],
                            item["role"],
                            now,
                            now,
                        )
                        for item in scope
                    ],
                )
            else:
                retained_scope = [
                    {
                        "vm_id": str(row["vm_id"]),
                        "role": row["approved_role"],
                    }
                    for row in connection.execute(
                        """
                        SELECT vm_id, approved_role
                        FROM infrastructure_host_vm_scope
                        WHERE host_id = ? ORDER BY vm_id
                        """,
                        (payload["host_id"],),
                    )
                ]
                if (
                    str(existing["cell_id"]) != payload["cell_id"]
                    or str(existing["display_name"]) != payload["display_name"]
                    or str(existing["failure_domain_label"])
                    != payload["failure_domain_label"]
                    or str(existing["platform"]) != "windows-hyperv"
                    or str(existing["scope_sha256"]) != scope_sha256
                    or not bool(existing["enabled"])
                    or retained_scope != scope
                ):
                    raise InfrastructureObservationError(
                        "host identity already exists with a different enrollment"
                    )
            return {
                "host_id": payload["host_id"],
                "cell_id": payload["cell_id"],
                "scope_sha256": scope_sha256,
                "approved_vm_count": len(scope),
            }

        if action == "agent.provision":
            host = connection.execute(
                """
                SELECT scope_sha256 FROM infrastructure_hosts
                WHERE host_id = ? AND enabled = 1
                """,
                (payload["host_id"],),
            ).fetchone()
            if host is None:
                raise InfrastructureObservationError(
                    "agent enrollment requires an enabled existing host"
                )
            scope_sha256 = str(host["scope_sha256"])
            existing = connection.execute(
                """
                SELECT host_id, assigned_scope_sha256, enabled
                FROM infrastructure_observer_agents WHERE agent_id = ?
                """,
                (payload["agent_id"],),
            ).fetchone()
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO infrastructure_observer_agents(
                        agent_id, host_id, assigned_scope_sha256, enabled,
                        last_contact_at, created_at, updated_at
                    ) VALUES (?, ?, ?, 1, NULL, ?, ?)
                    """,
                    (
                        payload["agent_id"],
                        payload["host_id"],
                        scope_sha256,
                        now,
                        now,
                    ),
                )
            elif (
                str(existing["host_id"]) != payload["host_id"]
                or str(existing["assigned_scope_sha256"]) != scope_sha256
                or not bool(existing["enabled"])
            ):
                raise InfrastructureObservationError(
                    "agent identity already exists with a different enrollment"
                )
            return {
                "agent_id": payload["agent_id"],
                "host_id": payload["host_id"],
                "assigned_scope_sha256": scope_sha256,
            }

        if action == "certificate.provision":
            if connection.execute(
                """
                SELECT 1 FROM infrastructure_observer_agents
                WHERE agent_id = ? AND enabled = 1
                """,
                (payload["agent_id"],),
            ).fetchone() is None:
                raise InfrastructureObservationError(
                    "certificate enrollment requires an enabled existing agent"
                )
            existing = connection.execute(
                """
                SELECT certificate_fingerprint_sha256, jws_key_id,
                       jws_algorithm, jws_spki_der_base64, jws_spki_sha256,
                       valid_from_epoch, valid_until_epoch, revoked_at
                FROM infrastructure_agent_certificates
                WHERE agent_id = ? AND certificate_generation = ?
                """,
                (
                    payload["agent_id"],
                    payload["certificate_generation"],
                ),
            ).fetchone()
            comparable = (
                payload["certificate_fingerprint_sha256"],
                payload["jws_key_id"],
                payload["jws_algorithm"],
                payload["jws_spki_der_base64"],
                payload["jws_spki_sha256"],
                payload["valid_from_epoch"],
                payload["valid_until_epoch"],
            )
            if existing is None:
                reused_signing_key = connection.execute(
                    """
                    SELECT agent_id, certificate_generation
                    FROM infrastructure_agent_certificates
                    WHERE jws_spki_sha256 = ?
                    """,
                    (payload["jws_spki_sha256"],),
                ).fetchone()
                if reused_signing_key is not None:
                    raise InfrastructureObservationError(
                        "JWS SPKI digest is already bound to another immutable "
                        "certificate generation; signing keys cannot be reused"
                    )
                prior_generation = connection.execute(
                    """
                    SELECT MAX(certificate_generation)
                    FROM infrastructure_agent_certificates
                    WHERE agent_id = ?
                    """,
                    (payload["agent_id"],),
                ).fetchone()[0]
                expected_generation = (
                    1
                    if prior_generation is None
                    else int(prior_generation) + 1
                )
                if payload["certificate_generation"] != expected_generation:
                    raise InfrastructureObservationError(
                        "new certificate generation must be the exact next "
                        "monotonic generation; existing generations are "
                        "retained for explicit overlap and revocation"
                    )
                _require_certificate_overlap_bound(
                    connection,
                    agent_id=str(payload["agent_id"]),
                    valid_from_epoch=int(payload["valid_from_epoch"]),
                    valid_until_epoch=int(payload["valid_until_epoch"]),
                )
                connection.execute(
                    """
                    INSERT INTO infrastructure_agent_certificates(
                        agent_id, certificate_generation,
                        certificate_fingerprint_sha256, jws_key_id,
                        jws_algorithm, jws_spki_der_base64, jws_spki_sha256,
                        valid_from_epoch, valid_until_epoch,
                        revoked_at, revocation_reason, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)
                    """,
                    (
                        payload["agent_id"],
                        payload["certificate_generation"],
                        *comparable,
                        now,
                    ),
                )
            elif (
                (
                    str(existing["certificate_fingerprint_sha256"]),
                    str(existing["jws_key_id"]),
                    str(existing["jws_algorithm"]),
                    str(existing["jws_spki_der_base64"]),
                    str(existing["jws_spki_sha256"]),
                    int(existing["valid_from_epoch"]),
                    int(existing["valid_until_epoch"]),
                )
                != comparable
                or existing["revoked_at"] is not None
            ):
                raise InfrastructureObservationError(
                    "certificate generation already exists with different "
                    "or revoked enrollment"
                )
            return {
                "agent_id": payload["agent_id"],
                "certificate_generation": payload["certificate_generation"],
                "certificate_fingerprint_sha256": payload[
                    "certificate_fingerprint_sha256"
                ],
                "jws_key_id": payload["jws_key_id"],
                "jws_algorithm": payload["jws_algorithm"],
                "jws_spki_der_base64": payload["jws_spki_der_base64"],
                "jws_spki_sha256": payload["jws_spki_sha256"],
                "valid_from_epoch": payload["valid_from_epoch"],
                "valid_until_epoch": payload["valid_until_epoch"],
            }

        if action == "certificate.revoke":
            existing = connection.execute(
                """
                SELECT revoked_at, revocation_reason
                FROM infrastructure_agent_certificates
                WHERE agent_id = ? AND certificate_generation = ?
                """,
                (
                    payload["agent_id"],
                    payload["certificate_generation"],
                ),
            ).fetchone()
            if existing is None:
                raise InfrastructureObservationError(
                    "certificate generation is not enrolled"
                )
            if existing["revoked_at"] is None:
                connection.execute(
                    """
                    UPDATE infrastructure_agent_certificates
                    SET revoked_at = ?, revocation_reason = ?
                    WHERE agent_id = ? AND certificate_generation = ?
                    """,
                    (
                        now,
                        payload["reason"],
                        payload["agent_id"],
                        payload["certificate_generation"],
                    ),
                )
                revoked_at = now
            elif str(existing["revocation_reason"]) != payload["reason"]:
                raise InfrastructureObservationError(
                    "certificate generation is already revoked for another reason"
                )
            else:
                revoked_at = str(existing["revoked_at"])
            return {
                "agent_id": payload["agent_id"],
                "certificate_generation": payload["certificate_generation"],
                "revoked_at": revoked_at,
                "reason": payload["reason"],
            }

        raise InfrastructureObservationError(
            "unsupported normalized infrastructure admin action"
        )

    def provision_cell(
        self,
        *,
        cell_id: str,
        name: str,
        region: str | None,
        classification_label: str | None,
    ) -> dict[str, Any]:
        cell = _canonical_uuid(cell_id, "cell_id", code="invalid_enrollment")
        normalized = {
            "name": _bounded_string(
                name, "name", minimum=1, maximum=128, code="invalid_enrollment"
            ),
            "region": _optional_bounded_string(
                region, "region", maximum=128, code="invalid_enrollment"
            ),
            "classification_label": _optional_bounded_string(
                classification_label,
                "classification_label",
                maximum=128,
                code="invalid_enrollment",
            ),
        }
        now = utc_timestamp(self._clock())
        with self._store() as store:
            with store.immediate_transaction(
                revision_kind="state", check_invariants=False
            ) as connection:
                existing = connection.execute(
                    """
                    SELECT name, region, classification_label, enabled
                    FROM infrastructure_cells WHERE cell_id = ?
                    """,
                    (cell,),
                ).fetchone()
                if existing is None:
                    connection.execute(
                        """
                        INSERT INTO infrastructure_cells(
                            cell_id, name, region, classification_label,
                            enabled, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, 1, ?, ?)
                        """,
                        (
                            cell,
                            normalized["name"],
                            normalized["region"],
                            normalized["classification_label"],
                            now,
                            now,
                        ),
                    )
                elif (
                    str(existing["name"]) != normalized["name"]
                    or existing["region"] != normalized["region"]
                    or existing["classification_label"]
                    != normalized["classification_label"]
                    or not bool(existing["enabled"])
                ):
                    raise InfrastructureObservationError(
                        "cell identity already exists with a different enrollment"
                    )
        return {"cell_id": cell, **normalized}

    def provision_host(
        self,
        *,
        host_id: str,
        cell_id: str,
        display_name: str,
        failure_domain_label: str,
        approved_virtual_machines: Mapping[str, str | None],
    ) -> dict[str, Any]:
        host = _canonical_uuid(host_id, "host_id", code="invalid_enrollment")
        cell = _canonical_uuid(cell_id, "cell_id", code="invalid_enrollment")
        display = _bounded_string(
            display_name,
            "display_name",
            minimum=1,
            maximum=128,
            code="invalid_enrollment",
        )
        failure_domain = _bounded_string(
            failure_domain_label,
            "failure_domain_label",
            minimum=1,
            maximum=256,
            code="invalid_enrollment",
        )
        normalized_scope = _normalized_scope(
            host, approved_virtual_machines, code="invalid_enrollment"
        )
        scope_sha256 = infrastructure_scope_sha256(
            host,
            {item["vm_id"]: item["role"] for item in normalized_scope},
        )
        now = utc_timestamp(self._clock())
        with self._store() as store:
            with store.immediate_transaction(
                revision_kind="state", check_invariants=False
            ) as connection:
                if connection.execute(
                    "SELECT 1 FROM infrastructure_cells "
                    "WHERE cell_id = ? AND enabled = 1",
                    (cell,),
                ).fetchone() is None:
                    raise InfrastructureObservationError(
                        "host enrollment requires an enabled existing cell"
                    )
                existing = connection.execute(
                    """
                    SELECT cell_id, display_name, failure_domain_label,
                           platform, scope_sha256, enabled
                    FROM infrastructure_hosts WHERE host_id = ?
                    """,
                    (host,),
                ).fetchone()
                if existing is None:
                    connection.execute(
                        """
                        INSERT INTO infrastructure_hosts(
                            host_id, cell_id, display_name, failure_domain_label,
                            platform, scope_sha256, enabled, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, 'windows-hyperv', ?, 1, ?, ?)
                        """,
                        (
                            host,
                            cell,
                            display,
                            failure_domain,
                            scope_sha256,
                            now,
                            now,
                        ),
                    )
                    connection.executemany(
                        """
                        INSERT INTO infrastructure_host_vm_scope(
                            host_id, vm_id, approved_role, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        [
                            (
                                host,
                                item["vm_id"],
                                item["role"],
                                now,
                                now,
                            )
                            for item in normalized_scope
                        ],
                    )
                else:
                    retained_scope = [
                        {
                            "vm_id": str(row["vm_id"]),
                            "role": row["approved_role"],
                        }
                        for row in connection.execute(
                            """
                            SELECT vm_id, approved_role
                            FROM infrastructure_host_vm_scope
                            WHERE host_id = ? ORDER BY vm_id
                            """,
                            (host,),
                        )
                    ]
                    if (
                        str(existing["cell_id"]) != cell
                        or str(existing["display_name"]) != display
                        or str(existing["failure_domain_label"]) != failure_domain
                        or str(existing["platform"]) != "windows-hyperv"
                        or str(existing["scope_sha256"]) != scope_sha256
                        or not bool(existing["enabled"])
                        or retained_scope != normalized_scope
                    ):
                        raise InfrastructureObservationError(
                            "host identity already exists with a different enrollment"
                        )
        return {
            "host_id": host,
            "cell_id": cell,
            "scope_sha256": scope_sha256,
            "approved_vm_count": len(normalized_scope),
        }

    def provision_agent(
        self,
        *,
        agent_id: str,
        host_id: str,
    ) -> dict[str, Any]:
        agent = _canonical_uuid(agent_id, "agent_id", code="invalid_enrollment")
        host = _canonical_uuid(host_id, "host_id", code="invalid_enrollment")
        now = utc_timestamp(self._clock())
        with self._store() as store:
            with store.immediate_transaction(
                revision_kind="state", check_invariants=False
            ) as connection:
                host_row = connection.execute(
                    """
                    SELECT scope_sha256 FROM infrastructure_hosts
                    WHERE host_id = ? AND enabled = 1
                    """,
                    (host,),
                ).fetchone()
                if host_row is None:
                    raise InfrastructureObservationError(
                        "agent enrollment requires an enabled existing host"
                    )
                scope_sha256 = str(host_row["scope_sha256"])
                existing = connection.execute(
                    """
                    SELECT host_id, assigned_scope_sha256, enabled
                    FROM infrastructure_observer_agents WHERE agent_id = ?
                    """,
                    (agent,),
                ).fetchone()
                if existing is None:
                    connection.execute(
                        """
                        INSERT INTO infrastructure_observer_agents(
                            agent_id, host_id, assigned_scope_sha256, enabled,
                            last_contact_at, created_at, updated_at
                        ) VALUES (?, ?, ?, 1, NULL, ?, ?)
                        """,
                        (agent, host, scope_sha256, now, now),
                    )
                elif (
                    str(existing["host_id"]) != host
                    or str(existing["assigned_scope_sha256"]) != scope_sha256
                    or not bool(existing["enabled"])
                ):
                    raise InfrastructureObservationError(
                        "agent identity already exists with a different enrollment"
                    )
        return {
            "agent_id": agent,
            "host_id": host,
            "assigned_scope_sha256": scope_sha256,
        }

    def provision_certificate(
        self,
        *,
        agent_id: str,
        certificate_generation: int,
        certificate_fingerprint_sha256: str,
        jws_key_id: str,
        jws_algorithm: str,
        jws_spki_der_base64: str,
        jws_spki_sha256: str,
        valid_from_epoch: int,
        valid_until_epoch: int,
    ) -> dict[str, Any]:
        agent = _canonical_uuid(agent_id, "agent_id", code="invalid_enrollment")
        generation = _integer(
            certificate_generation,
            "certificate_generation",
            minimum=1,
            maximum=2_147_483_647,
            code="invalid_enrollment",
        )
        fingerprint = _sha256(
            certificate_fingerprint_sha256,
            "certificate_fingerprint_sha256",
            code="invalid_enrollment",
        )
        key_id = _bounded_string(
            jws_key_id,
            "jws_key_id",
            minimum=1,
            maximum=128,
            code="invalid_enrollment",
        )
        algorithm = _bounded_string(
            jws_algorithm,
            "jws_algorithm",
            minimum=1,
            maximum=16,
            code="invalid_enrollment",
        )
        if algorithm != INFRASTRUCTURE_JWS_ALGORITHM:
            raise InfrastructureValidationError(
                "invalid_enrollment",
                "jws_algorithm must be the exact allowed PS256 algorithm.",
            )
        signing_material = normalize_ps256_spki(
            jws_spki_der_base64,
            jws_spki_sha256,
            code="invalid_enrollment",
        )
        valid_from = _integer(
            valid_from_epoch,
            "valid_from_epoch",
            minimum=0,
            maximum=MAX_SQLITE_INTEGER,
            code="invalid_enrollment",
        )
        valid_until = _integer(
            valid_until_epoch,
            "valid_until_epoch",
            minimum=1,
            maximum=MAX_SQLITE_INTEGER,
            code="invalid_enrollment",
        )
        _validate_certificate_validity_window(
            valid_from,
            valid_until,
            code="invalid_enrollment",
        )
        now = utc_timestamp(self._clock())
        with self._store() as store:
            with store.immediate_transaction(
                revision_kind="state", check_invariants=False
            ) as connection:
                if connection.execute(
                    "SELECT 1 FROM infrastructure_observer_agents "
                    "WHERE agent_id = ? AND enabled = 1",
                    (agent,),
                ).fetchone() is None:
                    raise InfrastructureObservationError(
                        "certificate enrollment requires an enabled existing agent"
                    )
                existing = connection.execute(
                    """
                    SELECT certificate_fingerprint_sha256, jws_key_id,
                           jws_algorithm, jws_spki_der_base64, jws_spki_sha256,
                           valid_from_epoch, valid_until_epoch, revoked_at
                    FROM infrastructure_agent_certificates
                    WHERE agent_id = ? AND certificate_generation = ?
                    """,
                    (agent, generation),
                ).fetchone()
                if existing is None:
                    reused_signing_key = connection.execute(
                        """
                        SELECT agent_id, certificate_generation
                        FROM infrastructure_agent_certificates
                        WHERE jws_spki_sha256 = ?
                        """,
                        (signing_material["jws_spki_sha256"],),
                    ).fetchone()
                    if reused_signing_key is not None:
                        raise InfrastructureObservationError(
                            "JWS SPKI digest is already bound to another "
                            "immutable certificate generation; signing keys "
                            "cannot be reused"
                        )
                    prior_generation = connection.execute(
                        """
                        SELECT MAX(certificate_generation)
                        FROM infrastructure_agent_certificates
                        WHERE agent_id = ?
                        """,
                        (agent,),
                    ).fetchone()[0]
                    expected_generation = (
                        1
                        if prior_generation is None
                        else int(prior_generation) + 1
                    )
                    if generation != expected_generation:
                        raise InfrastructureObservationError(
                            "new certificate generation must be the exact next "
                            "monotonic generation; existing generations are "
                            "retained for explicit overlap and revocation"
                        )
                    _require_certificate_overlap_bound(
                        connection,
                        agent_id=agent,
                        valid_from_epoch=valid_from,
                        valid_until_epoch=valid_until,
                    )
                    connection.execute(
                        """
                        INSERT INTO infrastructure_agent_certificates(
                            agent_id, certificate_generation,
                            certificate_fingerprint_sha256, jws_key_id,
                            jws_algorithm, jws_spki_der_base64, jws_spki_sha256,
                            valid_from_epoch, valid_until_epoch,
                            revoked_at, revocation_reason, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)
                        """,
                        (
                            agent,
                            generation,
                            fingerprint,
                            key_id,
                            algorithm,
                            signing_material["jws_spki_der_base64"],
                            signing_material["jws_spki_sha256"],
                            valid_from,
                            valid_until,
                            now,
                        ),
                    )
                elif (
                    str(existing["certificate_fingerprint_sha256"]) != fingerprint
                    or str(existing["jws_key_id"]) != key_id
                    or str(existing["jws_algorithm"]) != algorithm
                    or str(existing["jws_spki_der_base64"])
                    != signing_material["jws_spki_der_base64"]
                    or str(existing["jws_spki_sha256"])
                    != signing_material["jws_spki_sha256"]
                    or int(existing["valid_from_epoch"]) != valid_from
                    or int(existing["valid_until_epoch"]) != valid_until
                    or existing["revoked_at"] is not None
                ):
                    raise InfrastructureObservationError(
                        "certificate generation already exists with different "
                        "or revoked enrollment"
                    )
        return {
            "agent_id": agent,
            "certificate_generation": generation,
            "certificate_fingerprint_sha256": fingerprint,
            "jws_key_id": key_id,
            "jws_algorithm": algorithm,
            "jws_spki_der_base64": signing_material["jws_spki_der_base64"],
            "jws_spki_sha256": signing_material["jws_spki_sha256"],
            "valid_from_epoch": valid_from,
            "valid_until_epoch": valid_until,
        }

    def revoke_certificate(
        self,
        *,
        agent_id: str,
        certificate_generation: int,
        reason: str,
    ) -> dict[str, Any]:
        agent = _canonical_uuid(agent_id, "agent_id", code="invalid_enrollment")
        generation = _integer(
            certificate_generation,
            "certificate_generation",
            minimum=1,
            maximum=2_147_483_647,
            code="invalid_enrollment",
        )
        normalized_reason = _bounded_string(
            reason,
            "reason",
            minimum=1,
            maximum=256,
            code="invalid_enrollment",
        )
        now = utc_timestamp(self._clock())
        with self._store() as store:
            with store.immediate_transaction(
                revision_kind="state", check_invariants=False
            ) as connection:
                existing = connection.execute(
                    """
                    SELECT revoked_at, revocation_reason
                    FROM infrastructure_agent_certificates
                    WHERE agent_id = ? AND certificate_generation = ?
                    """,
                    (agent, generation),
                ).fetchone()
                if existing is None:
                    raise InfrastructureObservationError(
                        "certificate generation is not enrolled"
                    )
                if existing["revoked_at"] is None:
                    connection.execute(
                        """
                        UPDATE infrastructure_agent_certificates
                        SET revoked_at = ?, revocation_reason = ?
                        WHERE agent_id = ? AND certificate_generation = ?
                        """,
                        (now, normalized_reason, agent, generation),
                    )
                    revoked_at = now
                elif str(existing["revocation_reason"]) != normalized_reason:
                    raise InfrastructureObservationError(
                        "certificate generation is already revoked for another reason"
                    )
                else:
                    revoked_at = str(existing["revoked_at"])
        return {
            "agent_id": agent,
            "certificate_generation": generation,
            "revoked_at": revoked_at,
            "reason": normalized_reason,
        }

    def verification_context(
        self, arguments: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Return one exact public verification context without enumeration."""

        request = prepare_verification_context_arguments(arguments)
        now_epoch = int(self._clock())
        with CoordinatorStore.open_read_only(
            self.database_path,
            expected_uid=self.expected_uid,
            busy_timeout_ms=self.busy_timeout_ms,
        ) as store:
            with store.read_transaction() as connection:
                row = connection.execute(
                    """
                    SELECT certificate.agent_id,
                           certificate.certificate_generation,
                           certificate.certificate_fingerprint_sha256,
                           certificate.jws_key_id,
                           certificate.jws_algorithm,
                           certificate.jws_spki_der_base64,
                           certificate.jws_spki_sha256,
                           certificate.valid_from_epoch,
                           certificate.valid_until_epoch,
                           certificate.revoked_at,
                           certificate.revocation_reason,
                           agent.host_id,
                           agent.assigned_scope_sha256,
                           agent.enabled AS agent_enabled,
                           host.cell_id,
                           host.scope_sha256,
                           host.enabled AS host_enabled,
                           cell.enabled AS cell_enabled
                    FROM infrastructure_agent_certificates certificate
                    JOIN infrastructure_observer_agents agent USING(agent_id)
                    JOIN infrastructure_hosts host USING(host_id)
                    JOIN infrastructure_cells cell USING(cell_id)
                    WHERE certificate.certificate_fingerprint_sha256 = ?
                      AND certificate.certificate_generation = ?
                    """,
                    (
                        request["certificate_fingerprint_sha256"],
                        request["certificate_generation"],
                    ),
                ).fetchone()
        if row is None:
            raise InfrastructureValidationError(
                "certificate_not_enrolled",
                "The exact certificate fingerprint and generation are not enrolled.",
            )
        # Re-parse stored material on every lookup. A malformed or altered
        # authority row is corruption, never verification context.
        signing_material = normalize_ps256_spki(
            row["jws_spki_der_base64"],
            row["jws_spki_sha256"],
            code="invalid_enrolled_signing_material",
        )
        if str(row["jws_algorithm"]) != signing_material["jws_algorithm"]:
            raise InfrastructureValidationError(
                "invalid_enrolled_signing_material",
                "The enrolled JWS algorithm does not match its public key material.",
            )
        valid_from = int(row["valid_from_epoch"])
        valid_until = int(row["valid_until_epoch"])
        revoked = row["revoked_at"] is not None
        scope_current = str(row["assigned_scope_sha256"]) == str(
            row["scope_sha256"]
        )
        enrollment_enabled = (
            bool(row["agent_enabled"])
            and bool(row["host_enabled"])
            and bool(row["cell_enabled"])
        )
        return {
            "schema": INFRASTRUCTURE_VERIFICATION_CONTEXT_SCHEMA,
            "certificate_fingerprint_sha256": str(
                row["certificate_fingerprint_sha256"]
            ),
            "certificate_generation": int(row["certificate_generation"]),
            "jws_key_id": str(row["jws_key_id"]),
            "jws_algorithm": str(row["jws_algorithm"]),
            "jws_spki_der_base64": str(row["jws_spki_der_base64"]),
            "jws_spki_sha256": str(row["jws_spki_sha256"]),
            "agent_id": str(row["agent_id"]),
            "host_id": str(row["host_id"]),
            "cell_id": str(row["cell_id"]),
            "assigned_scope_sha256": str(row["assigned_scope_sha256"]),
            "host_scope_sha256": str(row["scope_sha256"]),
            "valid_from_epoch": valid_from,
            "valid_until_epoch": valid_until,
            "revoked": revoked,
            "revoked_at": row["revoked_at"],
            "revocation_reason": row["revocation_reason"],
            "agent_enabled": bool(row["agent_enabled"]),
            "host_enabled": bool(row["host_enabled"]),
            "cell_enabled": bool(row["cell_enabled"]),
            "scope_current": scope_current,
            "valid_at_lookup": valid_from <= now_epoch < valid_until,
            "eligible_at_lookup": (
                not revoked
                and enrollment_enabled
                and scope_current
                and valid_from <= now_epoch < valid_until
            ),
            "lookup_epoch": now_epoch,
        }

    def ingest(
        self,
        arguments: Mapping[str, Any],
        *,
        broker_operation_id: str,
        broker_peer_uid: int,
        broker_account_id: str,
    ) -> dict[str, Any]:
        """Accept or reject one report and commit its terminal audit atomically."""

        operation_id = _canonical_uuid(
            broker_operation_id,
            "broker_operation_id",
            code="invalid_operation_id",
        )
        peer_uid = _integer(
            broker_peer_uid,
            "broker_peer_uid",
            minimum=0,
            maximum=MAX_SQLITE_INTEGER,
            code="invalid_ingress_identity",
        )
        account_id = _bounded_identifier(
            broker_account_id,
            "broker_account_id",
            code="invalid_ingress_identity",
        )
        prepared = prepare_ingest_arguments(arguments)
        transport = VerifiedTransportEvidence.from_value(prepared["transport"])
        raw_observation = prepared["observation"]
        request_sha256 = hashlib.sha256(
            canonical_json(prepared).encode("utf-8")
        ).hexdigest()
        received_epoch = int(self._clock())
        received_at = utc_timestamp(received_epoch)

        # Denied or stale transport identities must not be able to grow the
        # root-owned broker CAS. This is only an early admission check; the
        # exact same authorization is repeated in the committing transaction
        # after publication so revocation and scope races still fail closed.
        preauthorization_error: InfrastructureIngestRejected | None = None
        preauthorized_certificate: sqlite3.Row | None = None
        with self._store() as store:
            with store.read_transaction() as connection:
                preauthorized_certificate = self._transport_enrollment_row(
                    connection,
                    transport=transport,
                )
                try:
                    if preauthorized_certificate is None:
                        raise InfrastructureValidationError(
                            "certificate_not_enrolled",
                            "Transport certificate generation is not enrolled.",
                        )
                    self._require_transport_enrollment(
                        connection,
                        transport=transport,
                        certificate_row=preauthorized_certificate,
                        now_epoch=received_epoch,
                        received_at=received_at,
                        update_contact=False,
                    )
                except InfrastructureValidationError as rejection:
                    preauthorization_error = InfrastructureIngestRejected(
                        rejection.code,
                        rejection.message,
                    )
        if preauthorization_error is not None:
            raise self._retain_metadata_only_rejection(
                operation_id=operation_id,
                peer_uid=peer_uid,
                account_id=account_id,
                error=preauthorization_error,
                transport=transport,
                request_sha256=request_sha256,
                raw_observation=raw_observation,
                received_at=received_at,
                certificate_row=preauthorized_certificate,
                report_operation_conflict=False,
            )
        try:
            staged_artifact = read_staged_signed_envelope(
                staging_root=self.ingress_staging_root,
                descriptor=prepared["artifact"],
                staging_uid=peer_uid,
            )
            _require_artifact_matches_verified_transport(
                staged_artifact.payload,
                raw_observation=raw_observation,
                transport=transport,
                enrolled_jws_spki_der_base64=str(
                    preauthorized_certificate["jws_spki_der_base64"]
                ),
            )
            published_artifact = publish_verified_staged_signed_envelope(
                broker_artifact_root=self.broker_artifact_root,
                staged=staged_artifact,
                broker_uid=self.expected_uid,
            )
        except (InfrastructureArtifactError, InfrastructureValidationError) as error:
            code = (
                error.code
                if isinstance(error, InfrastructureValidationError)
                else "artifact_verification_failed"
            )
            message = (
                error.message
                if isinstance(error, InfrastructureValidationError)
                else str(error)
            )
            raise self._retain_metadata_only_rejection(
                operation_id=operation_id,
                peer_uid=peer_uid,
                account_id=account_id,
                error=InfrastructureIngestRejected(code, message),
                transport=transport,
                request_sha256=request_sha256,
                raw_observation=raw_observation,
                received_at=received_at,
                certificate_row=preauthorized_certificate,
                report_operation_conflict=True,
            ) from None
        artifact_binding = published_artifact.binding(owner_uid=self.expected_uid)
        terminal_error: InfrastructureIngestRejected | None = None
        terminal_result: dict[str, Any] | None = None

        with self._store() as store:
            with store.immediate_transaction(
                max_seconds=10.0,
                revision_kind=None,
                check_invariants=False,
            ) as connection:
                existing = connection.execute(
                    """
                    SELECT request_sha256, outcome, result_json,
                           error_code, error_message
                    FROM infrastructure_ingest_operations
                    WHERE broker_operation_id = ?
                    """,
                    (operation_id,),
                ).fetchone()
                certificate_row = self._transport_enrollment_row(
                    connection,
                    transport=transport,
                )
                current_transport_rejection: (
                    InfrastructureValidationError | None
                ) = None
                try:
                    if certificate_row is None:
                        raise InfrastructureValidationError(
                            "certificate_not_enrolled",
                            "Transport certificate generation is not enrolled.",
                        )
                    self._require_transport_enrollment(
                        connection,
                        transport=transport,
                        certificate_row=certificate_row,
                        now_epoch=received_epoch,
                        received_at=received_at,
                    )
                except InfrastructureValidationError as rejection:
                    current_transport_rejection = rejection
                if existing is not None:
                    if current_transport_rejection is not None:
                        # An immutable terminal result is not a standing grant.
                        # Denied replays leave that result, its audit, contact
                        # freshness, and observation revision unchanged.
                        terminal_error = InfrastructureIngestRejected(
                            current_transport_rejection.code,
                            current_transport_rejection.message,
                        )
                    elif str(existing["request_sha256"]) != request_sha256:
                        error = InfrastructureIngestRejected(
                            "operation_id_conflict",
                            "Broker operation_id was already used for another "
                            "infrastructure report.",
                        )
                        self._insert_audit(
                            connection,
                            operation_id=operation_id,
                            peer_uid=peer_uid,
                            account_id=account_id,
                            outcome="rejected",
                            error=error,
                            transport=transport,
                            request_sha256=request_sha256,
                            raw_observation=raw_observation,
                            received_at=received_at,
                            certificate_row=certificate_row,
                            normalized=None,
                            artifact=artifact_binding,
                        )
                        self._advance_observation_revision(
                            connection, received_at=received_at
                        )
                        terminal_error = error
                    else:
                        self._advance_observation_revision(
                            connection, received_at=received_at
                        )
                        if str(existing["outcome"]) == "accepted":
                            result = json.loads(str(existing["result_json"]))
                            if not isinstance(result, dict):
                                raise InfrastructureObservationError(
                                    "accepted ingest replay result is invalid"
                                )
                            terminal_result = result
                        else:
                            terminal_error = InfrastructureIngestRejected(
                                str(existing["error_code"]),
                                str(existing["error_message"]),
                            )
                else:
                    normalized: dict[str, Any] | None = None
                    try:
                        if current_transport_rejection is not None:
                            raise current_transport_rejection
                        if certificate_row is None:
                            raise InfrastructureObservationError(
                                "eligible infrastructure transport lost enrollment row"
                            )
                        normalized = normalize_observation(raw_observation)
                        canonical_payload_sha256 = hashlib.sha256(
                            canonical_json(normalized).encode("utf-8")
                        ).hexdigest()
                        if (
                            canonical_payload_sha256
                            != transport.canonical_payload_sha256
                        ):
                            raise InfrastructureValidationError(
                                "canonical_payload_digest_mismatch",
                                "Verified transport payload digest does not "
                                "match the normalized canonical observation.",
                            )
                        self._require_observation_enrollment(
                            connection,
                            normalized=normalized,
                            certificate_row=certificate_row,
                        )
                        captured_epoch = _parse_utc_epoch(
                            normalized["captured_at"],
                            "captured_at",
                            code="invalid_captured_at",
                        )
                        if captured_epoch > received_epoch + MAX_FUTURE_SKEW_SECONDS:
                            raise InfrastructureValidationError(
                                "captured_at_in_future",
                                "Observation capture time exceeds the allowed "
                                "future skew.",
                            )
                        self._require_replay_advance(
                            connection,
                            normalized=normalized,
                            received_at=received_at,
                        )
                        terminal_result = self._commit_accepted(
                            connection,
                            operation_id=operation_id,
                            peer_uid=peer_uid,
                            account_id=account_id,
                            request_sha256=request_sha256,
                            transport=transport,
                            normalized=normalized,
                            certificate_row=certificate_row,
                            received_at=received_at,
                            artifact=artifact_binding,
                        )
                    except InfrastructureValidationError as rejection:
                        terminal_error = InfrastructureIngestRejected(
                            rejection.code, rejection.message
                        )
                        connection.execute(
                            """
                            INSERT INTO infrastructure_ingest_operations(
                                broker_operation_id, request_sha256, outcome,
                                result_json, error_code, error_message, completed_at
                            ) VALUES (?, ?, 'rejected', NULL, ?, ?, ?)
                            """,
                            (
                                operation_id,
                                request_sha256,
                                rejection.code,
                                rejection.message,
                                received_at,
                            ),
                        )
                        self._insert_audit(
                            connection,
                            operation_id=operation_id,
                            peer_uid=peer_uid,
                            account_id=account_id,
                            outcome="rejected",
                            error=terminal_error,
                            transport=transport,
                            request_sha256=request_sha256,
                            raw_observation=raw_observation,
                            received_at=received_at,
                            certificate_row=certificate_row,
                            normalized=normalized,
                            artifact=artifact_binding,
                        )
                        self._advance_observation_revision(
                            connection, received_at=received_at
                        )

        if terminal_error is not None:
            raise terminal_error
        if terminal_result is None:
            raise InfrastructureObservationError(
                "infrastructure ingest reached no terminal outcome"
            )
        return terminal_result

    def _retain_metadata_only_rejection(
        self,
        *,
        operation_id: str,
        peer_uid: int,
        account_id: str,
        error: InfrastructureIngestRejected,
        transport: VerifiedTransportEvidence,
        request_sha256: str,
        raw_observation: Mapping[str, Any],
        received_at: str,
        certificate_row: sqlite3.Row | None,
        report_operation_conflict: bool,
    ) -> InfrastructureIngestRejected:
        """Retain one idempotent pre-publication rejection without CAS bytes."""

        terminal_error = error
        with self._store() as store:
            with store.immediate_transaction(
                max_seconds=10.0,
                revision_kind=None,
                check_invariants=False,
            ) as connection:
                existing = connection.execute(
                    """
                    SELECT request_sha256, outcome, error_code, error_message
                    FROM infrastructure_ingest_operations
                    WHERE broker_operation_id = ?
                    """,
                    (operation_id,),
                ).fetchone()
                if existing is None:
                    connection.execute(
                        """
                        INSERT INTO infrastructure_ingest_operations(
                            broker_operation_id, request_sha256, outcome,
                            result_json, error_code, error_message, completed_at
                        ) VALUES (?, ?, 'rejected', NULL, ?, ?, ?)
                        """,
                        (
                            operation_id,
                            request_sha256,
                            error.code,
                            error.message,
                            received_at,
                        ),
                    )
                    self._insert_audit(
                        connection,
                        operation_id=operation_id,
                        peer_uid=peer_uid,
                        account_id=account_id,
                        outcome="rejected",
                        error=error,
                        transport=transport,
                        request_sha256=request_sha256,
                        raw_observation=raw_observation,
                        received_at=received_at,
                        certificate_row=certificate_row,
                        normalized=None,
                        artifact=None,
                    )
                    self._advance_observation_revision(
                        connection,
                        received_at=received_at,
                    )
                elif str(existing["request_sha256"]) == request_sha256:
                    if str(existing["outcome"]) == "rejected":
                        terminal_error = InfrastructureIngestRejected(
                            str(existing["error_code"]),
                            str(existing["error_message"]),
                        )
                elif report_operation_conflict:
                    terminal_error = InfrastructureIngestRejected(
                        "operation_id_conflict",
                        "Broker operation_id was already used for another "
                        "infrastructure report.",
                    )
                    self._insert_audit(
                        connection,
                        operation_id=operation_id,
                        peer_uid=peer_uid,
                        account_id=account_id,
                        outcome="rejected",
                        error=terminal_error,
                        transport=transport,
                        request_sha256=request_sha256,
                        raw_observation=raw_observation,
                        received_at=received_at,
                        certificate_row=certificate_row,
                        normalized=None,
                        artifact=None,
                    )
                    self._advance_observation_revision(
                        connection,
                        received_at=received_at,
                    )
        return terminal_error

    def read_projection(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        """Return a pure, bounded, immutable-ID-sorted infrastructure page."""

        request = prepare_read_arguments(arguments)
        generated_epoch = int(self._clock())
        generated_at = utc_timestamp(generated_epoch)
        after_host_id = request["after_host_id"]
        host_limit = int(request["host_limit"])
        vm_limit = int(request["vm_limit_per_host"])
        rejection_limit = int(request["rejection_limit_per_host"])
        with CoordinatorStore.open_read_only(
            self.database_path,
            expected_uid=self.expected_uid,
            busy_timeout_ms=self.busy_timeout_ms,
        ) as store:
            with store.read_transaction() as connection:
                host_rows = list(
                    connection.execute(
                        """
                        SELECT host.host_id, host.cell_id, host.display_name,
                               host.failure_domain_label, host.platform,
                               host.scope_sha256, host.enabled AS host_enabled,
                               cell.name AS cell_name, cell.region,
                               cell.classification_label,
                               cell.enabled AS cell_enabled,
                               current.observation_id, current.hostname,
                               current.platform_version,
                               current.management_addresses_json,
                               current.logical_cpu,
                               current.physical_memory_bytes,
                               current.uptime_seconds,
                               current.roster_complete,
                               current.roster_error_code,
                               current.last_captured_at,
                               current.last_accepted_at,
                               accepted.signature_verified,
                               accepted.evidence_available,
                               accepted.certificate_generation,
                               accepted.canonical_payload_sha256,
                               accepted.signed_envelope_sha256,
                               accepted.signed_envelope_locator,
                               accepted.signed_envelope_size_bytes,
                               accepted.observer_version,
                               (
                                 SELECT MAX(agent.last_contact_at)
                                 FROM infrastructure_observer_agents agent
                                 WHERE agent.host_id = host.host_id
                               ) AS last_contact_at,
                               (
                                 SELECT COUNT(*)
                                 FROM infrastructure_current_vms vm
                                 WHERE vm.host_id = host.host_id
                               ) AS current_vm_count,
                               (
                                 SELECT COUNT(*)
                                 FROM infrastructure_host_vm_scope scope
                                 WHERE scope.host_id = host.host_id
                               ) AS approved_vm_count
                        FROM infrastructure_hosts host
                        JOIN infrastructure_cells cell USING(cell_id)
                        LEFT JOIN infrastructure_current_hosts current
                          ON current.host_id = host.host_id
                        LEFT JOIN infrastructure_observations accepted
                          ON accepted.observation_id = current.observation_id
                        WHERE (? IS NULL OR host.host_id > ?)
                        ORDER BY host.host_id
                        LIMIT ?
                        """,
                        (after_host_id, after_host_id, host_limit + 1),
                    )
                )
                database_has_more = len(host_rows) > host_limit
                host_rows = host_rows[:host_limit]
                hosts: list[dict[str, Any]] = []
                host_list_bytes = 2
                byte_truncated = False
                maximum_envelope = {
                    "schema": "spectre.infrastructure.projection.v1",
                    "generated_at": generated_at,
                    "observation_cadence_seconds": OBSERVATION_CADENCE_SECONDS,
                    "stale_after_seconds": OBSERVATION_STALE_AFTER_SECONDS,
                    "sort": "host_id",
                    "after_host_id": after_host_id,
                    "host_limit": host_limit,
                    "vm_limit_per_host": vm_limit,
                    "rejection_limit_per_host": rejection_limit,
                    "hosts": [],
                    "has_more": True,
                    "next_after_host_id": str(uuid.UUID(int=0)),
                }
                projection_envelope_bytes = (
                    len(canonical_json(maximum_envelope).encode("utf-8")) - 2
                )
                for row in host_rows:
                    host_id = str(row["host_id"])
                    vm_rows = list(
                        connection.execute(
                            """
                            SELECT vm_id, observation_id, name, role, state,
                                   generation, vcpu, startup_memory_bytes,
                                   assigned_memory_bytes, ip_addresses_json,
                                   heartbeat, automatic_checkpoints, replication,
                                   first_seen_at, last_seen_at
                            FROM infrastructure_current_vms
                            WHERE host_id = ?
                            ORDER BY vm_id
                            LIMIT ?
                            """,
                            (host_id, vm_limit + 1),
                        )
                    )
                    vm_truncated = len(vm_rows) > vm_limit
                    vm_rows = vm_rows[:vm_limit]
                    missing_approved_rows = list(
                        connection.execute(
                            """
                            SELECT scope.vm_id, scope.approved_role
                            FROM infrastructure_host_vm_scope scope
                            LEFT JOIN infrastructure_current_vms current
                              ON current.host_id = scope.host_id
                             AND current.vm_id = scope.vm_id
                            WHERE scope.host_id = ?
                              AND current.vm_id IS NULL
                            ORDER BY scope.vm_id
                            LIMIT ?
                            """,
                            (host_id, vm_limit + 1),
                        )
                    )
                    missing_approved_truncated = (
                        len(missing_approved_rows) > vm_limit
                    )
                    missing_approved_rows = missing_approved_rows[:vm_limit]
                    rejection_rows = list(
                        connection.execute(
                            """
                            SELECT audit_id, broker_operation_id, rejection_code,
                                   rejection_message, received_at,
                                   certificate_generation,
                                   certificate_fingerprint_sha256,
                                   claimed_observation_id
                            FROM infrastructure_ingest_audit
                            WHERE host_id = ? AND outcome = 'rejected'
                            ORDER BY audit_sequence DESC
                            LIMIT ?
                            """,
                            (host_id, rejection_limit),
                        )
                    )
                    host_projection = {
                            "host_id": host_id,
                            "cell": {
                                "cell_id": str(row["cell_id"]),
                                "name": str(row["cell_name"]),
                                "region": row["region"],
                                "classification_label": row[
                                    "classification_label"
                                ],
                                "enabled": bool(row["cell_enabled"]),
                            },
                            "display_name": str(row["display_name"]),
                            "failure_domain_label": str(
                                row["failure_domain_label"]
                            ),
                            "platform": str(row["platform"]),
                            "scope_sha256": str(row["scope_sha256"]),
                            "enrollment_enabled": bool(row["host_enabled"]),
                            "last_contact_at": row["last_contact_at"],
                            "last_captured_at": row["last_captured_at"],
                            "last_accepted_at": row["last_accepted_at"],
                            "contact_freshness": _observation_freshness(
                                row["last_contact_at"], now_epoch=generated_epoch
                            ),
                            "capture_freshness": _observation_freshness(
                                row["last_captured_at"], now_epoch=generated_epoch
                            ),
                            "acceptance_freshness": _observation_freshness(
                                row["last_accepted_at"], now_epoch=generated_epoch
                            ),
                            "accepted_observation_id": row["observation_id"],
                            "signature_verified": (
                                bool(row["signature_verified"])
                                if row["signature_verified"] is not None
                                else False
                            ),
                            "evidence_available": (
                                bool(row["evidence_available"])
                                if row["evidence_available"] is not None
                                else False
                            ),
                            "verification": (
                                {
                                    "certificate_generation": int(
                                        row["certificate_generation"]
                                    ),
                                    "canonical_payload_sha256": str(
                                        row["canonical_payload_sha256"]
                                    ),
                                    "signed_envelope_sha256": str(
                                        row["signed_envelope_sha256"]
                                    ),
                                    "signed_envelope_locator": str(
                                        row["signed_envelope_locator"]
                                    ),
                                    "signed_envelope_size_bytes": int(
                                        row["signed_envelope_size_bytes"]
                                    ),
                                    "observer_version": str(
                                        row["observer_version"]
                                    ),
                                }
                                if row["observation_id"] is not None
                                else None
                            ),
                            "snapshot": (
                                {
                                    "hostname": str(row["hostname"]),
                                    "platform_version": str(
                                        row["platform_version"]
                                    ),
                                    "management_addresses": _json_string_list(
                                        row["management_addresses_json"]
                                    ),
                                    "logical_cpu": int(row["logical_cpu"]),
                                    "physical_memory_bytes": int(
                                        row["physical_memory_bytes"]
                                    ),
                                    "uptime_seconds": int(row["uptime_seconds"]),
                                    "roster_complete": bool(
                                        row["roster_complete"]
                                    ),
                                    "roster_error_code": row[
                                        "roster_error_code"
                                    ],
                                }
                                if row["observation_id"] is not None
                                else None
                            ),
                            "current_vm_count": int(row["current_vm_count"]),
                            "approved_vm_count": int(row["approved_vm_count"]),
                            "missing_approved_virtual_machines": [
                                {
                                    "vm_id": str(item["vm_id"]),
                                    "approved_role": item["approved_role"],
                                }
                                for item in missing_approved_rows
                            ],
                            "missing_approved_projection_truncated": (
                                missing_approved_truncated
                            ),
                            "virtual_machines": [
                                {
                                    "vm_id": str(vm["vm_id"]),
                                    "observation_id": str(
                                        vm["observation_id"]
                                    ),
                                    "name": str(vm["name"]),
                                    "role": vm["role"],
                                    "state": str(vm["state"]),
                                    "generation": int(vm["generation"]),
                                    "vcpu": int(vm["vcpu"]),
                                    "startup_memory_bytes": int(
                                        vm["startup_memory_bytes"]
                                    ),
                                    "assigned_memory_bytes": int(
                                        vm["assigned_memory_bytes"]
                                    ),
                                    "ip_addresses": _json_string_list(
                                        vm["ip_addresses_json"]
                                    ),
                                    "heartbeat": str(vm["heartbeat"]),
                                    "automatic_checkpoints": bool(
                                        vm["automatic_checkpoints"]
                                    ),
                                    "replication": str(vm["replication"]),
                                    "first_seen_at": str(vm["first_seen_at"]),
                                    "last_seen_at": str(vm["last_seen_at"]),
                                }
                                for vm in vm_rows
                            ],
                            "vm_projection_truncated": vm_truncated,
                            "recent_rejections": [
                                {
                                    "audit_id": str(item["audit_id"]),
                                    "broker_operation_id": str(
                                        item["broker_operation_id"]
                                    ),
                                    "code": str(item["rejection_code"]),
                                    "message": str(
                                        item["rejection_message"]
                                    ),
                                    "received_at": str(item["received_at"]),
                                    "certificate_generation": item[
                                        "certificate_generation"
                                    ],
                                    "certificate_fingerprint_sha256": item[
                                        "certificate_fingerprint_sha256"
                                    ],
                                    "claimed_observation_id": item[
                                        "claimed_observation_id"
                                    ],
                                }
                                for item in rejection_rows
                            ],
                        }
                    candidate_bytes = len(
                        canonical_json(host_projection).encode("utf-8")
                    )
                    candidate_list_bytes = (
                        host_list_bytes
                        + candidate_bytes
                        + (1 if hosts else 0)
                    )
                    if (
                        projection_envelope_bytes + candidate_list_bytes
                        > MAX_PROJECTION_BYTES
                    ):
                        if not hosts:
                            raise InfrastructureObservationError(
                                "one bounded infrastructure host projection "
                                "exceeds the broker-safe result limit"
                            )
                        byte_truncated = True
                        break
                    hosts.append(host_projection)
                    host_list_bytes = candidate_list_bytes
        has_more = database_has_more or byte_truncated
        projection = {
            "schema": "spectre.infrastructure.projection.v1",
            "generated_at": generated_at,
            "observation_cadence_seconds": OBSERVATION_CADENCE_SECONDS,
            "stale_after_seconds": OBSERVATION_STALE_AFTER_SECONDS,
            "sort": "host_id",
            "after_host_id": after_host_id,
            "host_limit": host_limit,
            "vm_limit_per_host": vm_limit,
            "rejection_limit_per_host": rejection_limit,
            "hosts": hosts,
            "has_more": has_more,
            "next_after_host_id": hosts[-1]["host_id"] if has_more and hosts else None,
        }
        if len(canonical_json(projection).encode("utf-8")) > MAX_PROJECTION_BYTES:
            raise InfrastructureObservationError(
                "bounded infrastructure projection exceeded its result limit"
            )
        return projection

    def _store(self) -> CoordinatorStore:
        return CoordinatorStore.open(
            self.database_path,
            expected_uid=self.expected_uid,
            busy_timeout_ms=self.busy_timeout_ms,
        )

    @staticmethod
    def _transport_enrollment_row(
        connection: sqlite3.Connection,
        *,
        transport: VerifiedTransportEvidence,
    ) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT certificate.agent_id,
                   certificate.certificate_generation,
                   certificate.certificate_fingerprint_sha256,
                   certificate.jws_key_id,
                   certificate.jws_algorithm,
                   certificate.jws_spki_der_base64,
                   certificate.jws_spki_sha256,
                   certificate.valid_from_epoch,
                   certificate.valid_until_epoch,
                   certificate.revoked_at,
                   agent.host_id,
                   agent.assigned_scope_sha256,
                   agent.enabled AS agent_enabled,
                   host.cell_id,
                   host.scope_sha256,
                   host.enabled AS host_enabled,
                   cell.enabled AS cell_enabled
            FROM infrastructure_agent_certificates certificate
            JOIN infrastructure_observer_agents agent USING(agent_id)
            JOIN infrastructure_hosts host USING(host_id)
            JOIN infrastructure_cells cell USING(cell_id)
            WHERE certificate.certificate_fingerprint_sha256 = ?
              AND certificate.certificate_generation = ?
            """,
            (
                transport.certificate_fingerprint_sha256,
                transport.certificate_generation,
            ),
        ).fetchone()

    @staticmethod
    def _require_transport_enrollment(
        connection: sqlite3.Connection,
        *,
        transport: VerifiedTransportEvidence,
        certificate_row: sqlite3.Row,
        now_epoch: int,
        received_at: str,
        update_contact: bool = True,
    ) -> None:
        row = certificate_row
        if (
            not transport.mtls_verified
            or not transport.jws_verified
        ):
            raise InfrastructureValidationError(
                "transport_not_verified",
                "Both mTLS and JWS verification evidence are required.",
            )
        if str(row["jws_key_id"]) != transport.jws_key_id:
            raise InfrastructureValidationError(
                "signing_key_mismatch",
                "JWS key identity does not match the enrolled certificate generation.",
            )
        if str(row["jws_algorithm"]) != transport.jws_algorithm:
            raise InfrastructureValidationError(
                "signing_algorithm_mismatch",
                "JWS algorithm does not match the enrolled certificate generation.",
            )
        if str(row["jws_spki_sha256"]) != transport.jws_spki_sha256:
            raise InfrastructureValidationError(
                "signing_key_material_mismatch",
                "Verified JWS public key material does not match the enrolled "
                "certificate generation.",
            )
        if row["revoked_at"] is not None:
            raise InfrastructureValidationError(
                "certificate_revoked",
                "Transport certificate generation is revoked.",
            )
        if now_epoch < int(row["valid_from_epoch"]):
            raise InfrastructureValidationError(
                "certificate_not_yet_valid",
                "Transport certificate generation is not yet valid.",
            )
        if now_epoch >= int(row["valid_until_epoch"]):
            raise InfrastructureValidationError(
                "certificate_expired",
                "Transport certificate generation is expired.",
            )
        if (
            not bool(row["agent_enabled"])
            or not bool(row["host_enabled"])
            or not bool(row["cell_enabled"])
        ):
            raise InfrastructureValidationError(
                "enrollment_disabled",
                "Infrastructure agent, host, or cell enrollment is disabled.",
            )
        if str(row["assigned_scope_sha256"]) != str(row["scope_sha256"]):
            raise InfrastructureValidationError(
                "enrollment_scope_stale",
                "Agent scope no longer matches its enrolled host scope.",
            )
        if update_contact:
            connection.execute(
                """
                UPDATE infrastructure_observer_agents
                SET last_contact_at = ?, updated_at = ?
                WHERE agent_id = ?
                """,
                (received_at, received_at, str(row["agent_id"])),
            )

    @staticmethod
    def _require_observation_enrollment(
        connection: sqlite3.Connection,
        *,
        normalized: Mapping[str, Any],
        certificate_row: sqlite3.Row,
    ) -> None:
        if normalized["agent_id"] != str(certificate_row["agent_id"]):
            raise InfrastructureValidationError(
                "agent_identity_mismatch",
                "Observation agent_id does not match the enrolled certificate.",
            )
        if normalized["host_id"] != str(certificate_row["host_id"]):
            raise InfrastructureValidationError(
                "host_identity_mismatch",
                "Observation host_id does not match the enrolled agent.",
            )
        if normalized["cell_id"] != str(certificate_row["cell_id"]):
            raise InfrastructureValidationError(
                "cell_identity_mismatch",
                "Observation cell_id does not match the enrolled host.",
            )
        scope_sha256 = str(certificate_row["scope_sha256"])
        if (
            normalized["evidence"]["scope_sha256"] != scope_sha256
            or str(certificate_row["assigned_scope_sha256"]) != scope_sha256
        ):
            raise InfrastructureValidationError(
                "scope_mismatch",
                "Observation scope digest does not match the enrolled host assignment.",
            )
        approved = {
            str(row["vm_id"]): row["approved_role"]
            for row in connection.execute(
                """
                SELECT vm_id, approved_role
                FROM infrastructure_host_vm_scope
                WHERE host_id = ? ORDER BY vm_id
                """,
                (normalized["host_id"],),
            )
        }
        for vm in normalized["virtual_machines"]:
            if vm["vm_id"] not in approved:
                raise InfrastructureValidationError(
                    "vm_scope_mismatch",
                    "Observation contains a VM outside the centrally approved scope.",
                )
            if vm["role"] != approved[vm["vm_id"]]:
                raise InfrastructureValidationError(
                    "vm_role_mismatch",
                    "Observation VM role does not match the centrally approved role.",
                )

    @staticmethod
    def _require_replay_advance(
        connection: sqlite3.Connection,
        *,
        normalized: Mapping[str, Any],
        received_at: str,
    ) -> None:
        if connection.execute(
            "SELECT 1 FROM infrastructure_observations WHERE observation_id = ?",
            (normalized["observation_id"],),
        ).fetchone() is not None:
            raise InfrastructureValidationError(
                "observation_replay",
                "Observation identity was already accepted.",
            )
        replay = connection.execute(
            """
            SELECT current_boot_id, last_sequence, last_captured_at
            FROM infrastructure_agent_replay_state WHERE agent_id = ?
            """,
            (normalized["agent_id"],),
        ).fetchone()
        sequence = int(normalized["sequence"])
        boot_id = str(normalized["agent_boot_id"])
        if replay is None:
            if sequence != 1:
                raise InfrastructureValidationError(
                    "initial_sequence_invalid",
                    "The first accepted report for an agent boot must use sequence 1.",
                )
            return
        if normalized["captured_at"] < str(replay["last_captured_at"]):
            raise InfrastructureValidationError(
                "captured_at_regression",
                "Observation capture time regressed behind the last accepted report.",
            )
        if boot_id == str(replay["current_boot_id"]):
            if sequence <= int(replay["last_sequence"]):
                raise InfrastructureValidationError(
                    "sequence_out_of_order",
                    "Observation sequence is replayed or out of order.",
                )
            return
        if connection.execute(
            """
            SELECT 1 FROM infrastructure_agent_boot_history
            WHERE agent_id = ? AND agent_boot_id = ?
            """,
            (normalized["agent_id"], boot_id),
        ).fetchone() is not None:
            raise InfrastructureValidationError(
                "agent_boot_replay",
                "A retired agent boot identity cannot become current again.",
            )
        if sequence != 1:
            raise InfrastructureValidationError(
                "new_boot_sequence_invalid",
                "A new agent boot identity must begin with sequence 1.",
            )

    def _commit_accepted(
        self,
        connection: sqlite3.Connection,
        *,
        operation_id: str,
        peer_uid: int,
        account_id: str,
        request_sha256: str,
        transport: VerifiedTransportEvidence,
        normalized: Mapping[str, Any],
        certificate_row: sqlite3.Row,
        received_at: str,
        artifact: Mapping[str, Any],
    ) -> dict[str, Any]:
        observation_id = str(normalized["observation_id"])
        host_id = str(normalized["host_id"])
        agent_id = str(normalized["agent_id"])
        boot_id = str(normalized["agent_boot_id"])
        sequence = int(normalized["sequence"])
        roster_complete = bool(normalized["roster_complete"])
        connection.execute(
            """
            INSERT INTO infrastructure_observations(
                observation_id, cell_id, host_id, agent_id,
                certificate_generation, agent_boot_id, sequence,
                captured_at, received_at, accepted_at,
                roster_complete, roster_error_code, scope_sha256,
                canonical_payload_sha256, observer_version, vm_count,
                signature_verified, evidence_available,
                signed_envelope_sha256, signed_envelope_locator,
                signed_envelope_size_bytes
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1,
                ?, ?, ?
            )
            """,
            (
                observation_id,
                normalized["cell_id"],
                host_id,
                agent_id,
                transport.certificate_generation,
                boot_id,
                sequence,
                normalized["captured_at"],
                received_at,
                received_at,
                int(roster_complete),
                normalized["roster_error_code"],
                normalized["evidence"]["scope_sha256"],
                transport.canonical_payload_sha256,
                normalized["evidence"]["observer_version"],
                len(normalized["virtual_machines"]),
                artifact["sha256"],
                artifact["locator"],
                artifact["size_bytes"],
            ),
        )
        host = normalized["host"]
        connection.execute(
            """
            INSERT INTO infrastructure_current_hosts(
                host_id, observation_id, hostname, platform, platform_version,
                management_addresses_json, logical_cpu,
                physical_memory_bytes, uptime_seconds,
                roster_complete, roster_error_code,
                last_captured_at, last_accepted_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(host_id) DO UPDATE SET
                observation_id = excluded.observation_id,
                hostname = excluded.hostname,
                platform = excluded.platform,
                platform_version = excluded.platform_version,
                management_addresses_json = excluded.management_addresses_json,
                logical_cpu = excluded.logical_cpu,
                physical_memory_bytes = excluded.physical_memory_bytes,
                uptime_seconds = excluded.uptime_seconds,
                roster_complete = excluded.roster_complete,
                roster_error_code = excluded.roster_error_code,
                last_captured_at = excluded.last_captured_at,
                last_accepted_at = excluded.last_accepted_at
            """,
            (
                host_id,
                observation_id,
                host["hostname"],
                host["platform"],
                host["platform_version"],
                canonical_json(host["management_addresses"]),
                host["logical_cpu"],
                host["physical_memory_bytes"],
                host["uptime_seconds"],
                int(roster_complete),
                normalized["roster_error_code"],
                normalized["captured_at"],
                received_at,
            ),
        )
        reported_ids: list[str] = []
        for vm in normalized["virtual_machines"]:
            reported_ids.append(str(vm["vm_id"]))
            connection.execute(
                """
                INSERT INTO infrastructure_current_vms(
                    host_id, vm_id, observation_id, name, role, state,
                    generation, vcpu, startup_memory_bytes,
                    assigned_memory_bytes, ip_addresses_json, heartbeat,
                    automatic_checkpoints, replication,
                    first_seen_at, last_seen_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(host_id, vm_id) DO UPDATE SET
                    observation_id = excluded.observation_id,
                    name = excluded.name,
                    role = excluded.role,
                    state = excluded.state,
                    generation = excluded.generation,
                    vcpu = excluded.vcpu,
                    startup_memory_bytes = excluded.startup_memory_bytes,
                    assigned_memory_bytes = excluded.assigned_memory_bytes,
                    ip_addresses_json = excluded.ip_addresses_json,
                    heartbeat = excluded.heartbeat,
                    automatic_checkpoints = excluded.automatic_checkpoints,
                    replication = excluded.replication,
                    last_seen_at = excluded.last_seen_at
                """,
                (
                    host_id,
                    vm["vm_id"],
                    observation_id,
                    vm["name"],
                    vm["role"],
                    vm["state"],
                    vm["generation"],
                    vm["vcpu"],
                    vm["startup_memory_bytes"],
                    vm["assigned_memory_bytes"],
                    canonical_json(vm["ip_addresses"]),
                    vm["heartbeat"],
                    int(vm["automatic_checkpoints"]),
                    vm["replication"],
                    received_at,
                    received_at,
                ),
            )
        if roster_complete:
            if reported_ids:
                placeholders = ",".join("?" for _ in reported_ids)
                connection.execute(
                    f"""
                    DELETE FROM infrastructure_current_vms
                    WHERE host_id = ? AND vm_id NOT IN ({placeholders})
                    """,
                    (host_id, *reported_ids),
                )
            else:
                connection.execute(
                    "DELETE FROM infrastructure_current_vms WHERE host_id = ?",
                    (host_id,),
                )
        replay = connection.execute(
            """
            SELECT current_boot_id FROM infrastructure_agent_replay_state
            WHERE agent_id = ?
            """,
            (agent_id,),
        ).fetchone()
        if replay is None or str(replay["current_boot_id"]) != boot_id:
            connection.execute(
                """
                INSERT INTO infrastructure_agent_boot_history(
                    agent_id, agent_boot_id, first_sequence, last_sequence,
                    first_accepted_at, last_accepted_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    agent_id,
                    boot_id,
                    sequence,
                    sequence,
                    received_at,
                    received_at,
                ),
            )
        else:
            connection.execute(
                """
                UPDATE infrastructure_agent_boot_history
                SET last_sequence = ?, last_accepted_at = ?
                WHERE agent_id = ? AND agent_boot_id = ?
                """,
                (sequence, received_at, agent_id, boot_id),
            )
        connection.execute(
            """
            INSERT INTO infrastructure_agent_replay_state(
                agent_id, current_boot_id, last_sequence,
                last_observation_id, last_captured_at,
                last_accepted_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET
                current_boot_id = excluded.current_boot_id,
                last_sequence = excluded.last_sequence,
                last_observation_id = excluded.last_observation_id,
                last_captured_at = excluded.last_captured_at,
                last_accepted_at = excluded.last_accepted_at,
                updated_at = excluded.updated_at
            """,
            (
                agent_id,
                boot_id,
                sequence,
                observation_id,
                normalized["captured_at"],
                received_at,
                received_at,
            ),
        )
        current_vm_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM infrastructure_current_vms WHERE host_id = ?",
                (host_id,),
            ).fetchone()[0]
        )
        result = {
            "status": "accepted",
            "observation_id": observation_id,
            "cell_id": normalized["cell_id"],
            "host_id": host_id,
            "agent_id": agent_id,
            "agent_boot_id": boot_id,
            "sequence": sequence,
            "roster_complete": roster_complete,
            "reported_vm_count": len(normalized["virtual_machines"]),
            "current_vm_count": current_vm_count,
            "accepted_at": received_at,
            "evidence_available": True,
            "signed_envelope_sha256": artifact["sha256"],
            "signed_envelope_locator": artifact["locator"],
        }
        connection.execute(
            """
            INSERT INTO infrastructure_ingest_operations(
                broker_operation_id, request_sha256, outcome,
                result_json, error_code, error_message, completed_at
            ) VALUES (?, ?, 'accepted', ?, NULL, NULL, ?)
            """,
            (
                operation_id,
                request_sha256,
                canonical_json(result),
                received_at,
            ),
        )
        self._insert_audit(
            connection,
            operation_id=operation_id,
            peer_uid=peer_uid,
            account_id=account_id,
            outcome="accepted",
            error=None,
            transport=transport,
            request_sha256=request_sha256,
            raw_observation=normalized,
            received_at=received_at,
            certificate_row=certificate_row,
            normalized=normalized,
            artifact=artifact,
        )
        self._advance_observation_revision(
            connection, received_at=received_at
        )
        return result

    @staticmethod
    def _insert_audit(
        connection: sqlite3.Connection,
        *,
        operation_id: str,
        peer_uid: int,
        account_id: str,
        outcome: str,
        error: InfrastructureValidationError | None,
        transport: VerifiedTransportEvidence,
        request_sha256: str,
        raw_observation: Mapping[str, Any],
        received_at: str,
        certificate_row: sqlite3.Row | None,
        normalized: Mapping[str, Any] | None,
        artifact: Mapping[str, Any] | None,
    ) -> None:
        candidate = _candidate_identity(raw_observation)
        source = normalized or candidate
        connection.execute(
            """
            INSERT INTO infrastructure_ingest_audit(
                audit_id, broker_operation_id, broker_peer_uid,
                broker_account_id, outcome, rejection_code,
                rejection_message, certificate_fingerprint_sha256,
                certificate_generation, agent_id, cell_id, host_id,
                observation_id, agent_boot_id, sequence, captured_at,
                claimed_agent_id, claimed_cell_id, claimed_host_id,
                claimed_observation_id, claimed_agent_boot_id,
                claimed_sequence, claimed_captured_at,
                request_sha256, canonical_payload_sha256, received_at,
                signature_verified, mtls_verified,
                signed_envelope_sha256, signed_envelope_locator,
                signed_envelope_size_bytes, evidence_available
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                str(uuid.uuid4()),
                operation_id,
                peer_uid,
                account_id,
                outcome,
                error.code if error else None,
                error.message if error else None,
                transport.certificate_fingerprint_sha256,
                transport.certificate_generation,
                (
                    str(certificate_row["agent_id"])
                    if certificate_row is not None
                    else None
                ),
                (
                    str(certificate_row["cell_id"])
                    if certificate_row is not None
                    else None
                ),
                (
                    str(certificate_row["host_id"])
                    if certificate_row is not None
                    else None
                ),
                source.get("observation_id") if outcome == "accepted" else None,
                source.get("agent_boot_id") if outcome == "accepted" else None,
                source.get("sequence") if outcome == "accepted" else None,
                source.get("captured_at") if outcome == "accepted" else None,
                source.get("agent_id"),
                source.get("cell_id"),
                source.get("host_id"),
                source.get("observation_id"),
                source.get("agent_boot_id"),
                source.get("sequence"),
                source.get("captured_at"),
                request_sha256,
                transport.canonical_payload_sha256,
                received_at,
                int(artifact is not None),
                int(transport.mtls_verified),
                artifact["sha256"] if artifact is not None else None,
                artifact["locator"] if artifact is not None else None,
                artifact["size_bytes"] if artifact is not None else None,
                int(artifact is not None),
            ),
        )

    @staticmethod
    def _advance_observation_revision(
        connection: sqlite3.Connection, *, received_at: str
    ) -> None:
        connection.execute(
            """
            UPDATE schema_metadata
            SET observation_revision = observation_revision + 1,
                updated_at = ?
            WHERE singleton = 1
            """,
            (received_at,),
        )


def _require_artifact_matches_verified_transport(
    compact_jws: bytes,
    *,
    raw_observation: Mapping[str, Any],
    transport: VerifiedTransportEvidence,
    enrolled_jws_spki_der_base64: str,
) -> None:
    """Cryptographically verify and bind retained JWS bytes in the broker."""

    try:
        text = compact_jws.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise InfrastructureValidationError(
            "artifact_jws_invalid",
            "Retained signed-envelope artifact is not ASCII compact JWS.",
        ) from error
    segments = text.split(".")
    if len(segments) != 3 or any(not segment for segment in segments):
        raise InfrastructureValidationError(
            "artifact_jws_invalid",
            "Retained signed-envelope artifact is not a three-segment compact JWS.",
        )
    header_bytes = _canonical_base64url_decode(
        segments[0], field="protected header", maximum=4 * 1024
    )
    payload_bytes = _canonical_base64url_decode(
        segments[1], field="payload", maximum=MAX_OUTER_INGEST_BYTES
    )
    signature = _canonical_base64url_decode(
        segments[2], field="signature", maximum=1024
    )
    if len(signature) < 384:
        raise InfrastructureValidationError(
            "artifact_jws_invalid",
            "Retained PS256 signature is shorter than an RSA-3072 signature.",
        )

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise InfrastructureValidationError(
                    "artifact_jws_invalid",
                    "Retained JWS protected header contains a duplicate field.",
                )
            result[key] = value
        return result

    try:
        header = json.loads(
            header_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=object_pairs,
            parse_float=lambda _value: (_ for _ in ()).throw(
                InfrastructureValidationError(
                    "artifact_jws_invalid",
                    "Retained JWS protected header cannot contain a float.",
                )
            ),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                InfrastructureValidationError(
                    "artifact_jws_invalid",
                    "Retained JWS protected header cannot contain a non-finite number.",
                )
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InfrastructureValidationError(
            "artifact_jws_invalid",
            "Retained JWS protected header is not strict JSON.",
        ) from error
    if not isinstance(header, dict) or set(header) != {
        "alg",
        "typ",
        "kid",
        "x5t#S256",
        "cert_generation",
        "spki_sha256",
    }:
        raise InfrastructureValidationError(
            "artifact_jws_invalid",
            "Retained JWS protected header fields are not the closed v1 contract.",
        )
    _require_nfc_json_strings(header)
    if canonical_json(header).encode("utf-8") != header_bytes:
        raise InfrastructureValidationError(
            "artifact_jws_invalid",
            "Retained JWS protected header is not canonical JSON.",
        )
    expected_thumbprint = _canonical_base64url_encode(
        bytes.fromhex(transport.certificate_fingerprint_sha256)
    )
    if (
        header.get("alg") != INFRASTRUCTURE_JWS_ALGORITHM
        or header.get("typ") != INFRASTRUCTURE_JWS_TYPE
        or header.get("kid") != transport.jws_key_id
        or header.get("x5t#S256") != expected_thumbprint
        or header.get("cert_generation") != transport.certificate_generation
        or header.get("spki_sha256") != transport.jws_spki_sha256
    ):
        raise InfrastructureValidationError(
            "artifact_transport_binding_mismatch",
            "Retained JWS header does not match the verified transport identity.",
        )
    parsed_payload, payload_sha256 = parse_canonical_observation_payload(
        payload_bytes, maximum_bytes=MAX_OUTER_INGEST_BYTES
    )
    if (
        payload_sha256 != transport.canonical_payload_sha256
        or canonical_json(parsed_payload) != canonical_json(raw_observation)
    ):
        raise InfrastructureValidationError(
            "artifact_payload_binding_mismatch",
            "Retained JWS payload does not match the broker ingest observation.",
        )
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
    except ImportError as error:
        raise InfrastructureValidationError(
            "artifact_signature_verifier_unavailable",
            "The broker PS256 verifier is not installed in its pinned "
            "authority runtime.",
        ) from error
    try:
        spki_der = base64.b64decode(
            enrolled_jws_spki_der_base64,
            validate=True,
        )
        public_key = serialization.load_der_public_key(spki_der)
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("enrolled JWS key is not RSA")
        public_key.verify(
            signature,
            f"{segments[0]}.{segments[1]}".encode("ascii"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=hashes.SHA256().digest_size,
            ),
            hashes.SHA256(),
        )
    except (InvalidSignature, ValueError, TypeError, binascii.Error) as error:
        raise InfrastructureValidationError(
            "artifact_signature_invalid",
            "Retained JWS PS256 signature does not verify against the enrolled "
            "certificate-generation key.",
        ) from error


def _canonical_base64url_decode(
    value: str, *, field: str, maximum: int
) -> bytes:
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
        raise InfrastructureValidationError(
            "artifact_jws_invalid",
            f"Retained JWS {field} is not canonical base64url.",
        )
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError) as error:
        raise InfrastructureValidationError(
            "artifact_jws_invalid",
            f"Retained JWS {field} cannot be decoded.",
        ) from error
    if len(decoded) > maximum or _canonical_base64url_encode(decoded) != value:
        raise InfrastructureValidationError(
            "artifact_jws_invalid",
            f"Retained JWS {field} exceeds bounds or is not canonical.",
        )
    return decoded


def _canonical_base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def normalize_observation(value: Any) -> dict[str, Any]:
    """Return one strict, detached, closed v1 observation."""

    if not isinstance(value, dict):
        raise InfrastructureValidationError(
            "invalid_observation", "Observation must be a JSON object."
        )
    if _encoded_size(value, code="invalid_observation") > MAX_OBSERVATION_BYTES:
        raise InfrastructureValidationError(
            "observation_oversized",
            "Observation exceeds the v1 payload byte bound.",
        )
    _require_exact_fields(
        value,
        {
            "schema",
            "observation_id",
            "cell_id",
            "host_id",
            "agent_id",
            "agent_boot_id",
            "sequence",
            "captured_at",
            "roster_complete",
            "roster_error_code",
            "host",
            "virtual_machines",
            "evidence",
        },
        code="invalid_observation",
        subject="observation",
    )
    if value["schema"] != INFRASTRUCTURE_SCHEMA:
        raise InfrastructureValidationError(
            "unsupported_observation_schema",
            "Observation schema is not supported.",
        )
    if type(value["roster_complete"]) is not bool:
        raise InfrastructureValidationError(
            "invalid_observation", "roster_complete must be a boolean."
        )
    roster_error_code = value["roster_error_code"]
    if value["roster_complete"]:
        if roster_error_code is not None:
            raise InfrastructureValidationError(
                "invalid_observation",
                "A complete roster cannot carry roster_error_code.",
            )
    else:
        if (
            not isinstance(roster_error_code, str)
            or not _ERROR_CODE.fullmatch(roster_error_code)
        ):
            raise InfrastructureValidationError(
                "invalid_observation",
                "An incomplete roster requires a bounded roster_error_code.",
            )
    normalized: dict[str, Any] = {
        "schema": INFRASTRUCTURE_SCHEMA,
        "observation_id": _canonical_uuid(
            value["observation_id"], "observation_id", code="invalid_observation"
        ),
        "cell_id": _canonical_uuid(
            value["cell_id"], "cell_id", code="invalid_observation"
        ),
        "host_id": _canonical_uuid(
            value["host_id"], "host_id", code="invalid_observation"
        ),
        "agent_id": _canonical_uuid(
            value["agent_id"], "agent_id", code="invalid_observation"
        ),
        "agent_boot_id": _canonical_uuid(
            value["agent_boot_id"], "agent_boot_id", code="invalid_observation"
        ),
        "sequence": _integer(
            value["sequence"],
            "sequence",
            minimum=1,
            maximum=MAX_SQLITE_INTEGER,
            code="invalid_observation",
        ),
        "captured_at": _canonical_utc(
            value["captured_at"], "captured_at", code="invalid_observation"
        ),
        "roster_complete": value["roster_complete"],
        "roster_error_code": roster_error_code,
        "host": _normalize_host(value["host"]),
        "virtual_machines": _normalize_virtual_machines(
            value["virtual_machines"]
        ),
        "evidence": _normalize_evidence(value["evidence"]),
    }
    return normalized


def observation_payload_sha256(value: Mapping[str, Any]) -> str:
    """Compute the digest of one canonical payload with no self-digest field."""

    detached = _detached_json(value, code="invalid_observation")
    return hashlib.sha256(canonical_json(detached).encode("utf-8")).hexdigest()


def _normalize_host(value: Any) -> dict[str, Any]:
    _require_exact_fields(
        value,
        {
            "hostname",
            "platform",
            "platform_version",
            "management_addresses",
            "logical_cpu",
            "physical_memory_bytes",
            "uptime_seconds",
        },
        code="invalid_observation",
        subject="host",
    )
    if value["platform"] != "windows-hyperv":
        raise InfrastructureValidationError(
            "platform_mismatch", "v1 accepts only the windows-hyperv platform."
        )
    return {
        "hostname": _bounded_string(
            value["hostname"],
            "hostname",
            minimum=1,
            maximum=253,
            code="invalid_observation",
        ),
        "platform": "windows-hyperv",
        "platform_version": _bounded_string(
            value["platform_version"],
            "platform_version",
            minimum=1,
            maximum=128,
            code="invalid_observation",
        ),
        "management_addresses": _ip_list(
            value["management_addresses"],
            "management_addresses",
            maximum=MAX_MANAGEMENT_ADDRESSES,
        ),
        "logical_cpu": _integer(
            value["logical_cpu"],
            "logical_cpu",
            minimum=1,
            maximum=4096,
            code="invalid_observation",
        ),
        "physical_memory_bytes": _integer(
            value["physical_memory_bytes"],
            "physical_memory_bytes",
            minimum=1,
            maximum=MAX_SQLITE_INTEGER,
            code="invalid_observation",
        ),
        "uptime_seconds": _integer(
            value["uptime_seconds"],
            "uptime_seconds",
            minimum=0,
            maximum=MAX_SQLITE_INTEGER,
            code="invalid_observation",
        ),
    }


def _normalize_virtual_machines(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise InfrastructureValidationError(
            "invalid_observation", "virtual_machines must be a JSON array."
        )
    if len(value) > MAX_VIRTUAL_MACHINES:
        raise InfrastructureValidationError(
            "observation_oversized",
            "virtual_machines exceeds the v1 host bound.",
        )
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in value:
        _require_exact_fields(
            item,
            {
                "vm_id",
                "name",
                "role",
                "state",
                "generation",
                "vcpu",
                "startup_memory_bytes",
                "assigned_memory_bytes",
                "ip_addresses",
                "heartbeat",
                "automatic_checkpoints",
                "replication",
            },
            code="invalid_observation",
            subject="virtual machine",
        )
        vm_id = _canonical_uuid(
            item["vm_id"], "vm_id", code="invalid_observation"
        )
        if vm_id in seen:
            raise InfrastructureValidationError(
                "duplicate_vm_identity",
                "virtual_machines contains a duplicate VM identity.",
            )
        seen.add(vm_id)
        state = item["state"]
        if state not in {
            "running",
            "off",
            "paused",
            "saved",
            "starting",
            "stopping",
            "unknown",
        }:
            raise InfrastructureValidationError(
                "invalid_observation", "VM state is not supported."
            )
        heartbeat = item["heartbeat"]
        if heartbeat not in {"ok", "degraded", "unknown", "not-running"}:
            raise InfrastructureValidationError(
                "invalid_observation", "VM heartbeat is not supported."
            )
        replication = item["replication"]
        if replication not in {"disabled", "enabled", "unknown"}:
            raise InfrastructureValidationError(
                "invalid_observation", "VM replication value is not supported."
            )
        if type(item["automatic_checkpoints"]) is not bool:
            raise InfrastructureValidationError(
                "invalid_observation",
                "automatic_checkpoints must be a boolean.",
            )
        normalized.append(
            {
                "vm_id": vm_id,
                "name": _bounded_string(
                    item["name"],
                    "name",
                    minimum=1,
                    maximum=256,
                    code="invalid_observation",
                ),
                "role": _role(item["role"], code="invalid_observation"),
                "state": state,
                "generation": _integer(
                    item["generation"],
                    "generation",
                    minimum=1,
                    maximum=2,
                    code="invalid_observation",
                ),
                "vcpu": _integer(
                    item["vcpu"],
                    "vcpu",
                    minimum=1,
                    maximum=2048,
                    code="invalid_observation",
                ),
                "startup_memory_bytes": _integer(
                    item["startup_memory_bytes"],
                    "startup_memory_bytes",
                    minimum=0,
                    maximum=MAX_SQLITE_INTEGER,
                    code="invalid_observation",
                ),
                "assigned_memory_bytes": _integer(
                    item["assigned_memory_bytes"],
                    "assigned_memory_bytes",
                    minimum=0,
                    maximum=MAX_SQLITE_INTEGER,
                    code="invalid_observation",
                ),
                "ip_addresses": _ip_list(
                    item["ip_addresses"],
                    "ip_addresses",
                    maximum=MAX_VM_ADDRESSES,
                ),
                "heartbeat": heartbeat,
                "automatic_checkpoints": item["automatic_checkpoints"],
                "replication": replication,
            }
        )
    return sorted(normalized, key=lambda item: item["vm_id"])


def _normalize_evidence(value: Any) -> dict[str, Any]:
    _require_exact_fields(
        value,
        {"observer_version", "scope_sha256"},
        code="invalid_observation",
        subject="evidence",
    )
    observer_version = _bounded_string(
        value["observer_version"],
        "observer_version",
        minimum=5,
        maximum=64,
        code="invalid_observation",
    )
    if not _SEMVER.fullmatch(observer_version):
        raise InfrastructureValidationError(
            "invalid_observation",
            "observer_version must be semantic version text.",
        )
    return {
        "observer_version": observer_version,
        "scope_sha256": _sha256(
            value["scope_sha256"],
            "scope_sha256",
            code="invalid_observation",
        ),
    }


def _normalized_scope(
    host_id: str,
    approved_virtual_machines: Mapping[str, str | None],
    *,
    code: str,
) -> list[dict[str, Any]]:
    if not isinstance(approved_virtual_machines, Mapping):
        raise InfrastructureValidationError(
            code, "approved_virtual_machines must be an immutable-ID mapping."
        )
    if len(approved_virtual_machines) > MAX_VIRTUAL_MACHINES:
        raise InfrastructureValidationError(
            code, "approved_virtual_machines exceeds the v1 host bound."
        )
    normalized = [
        {
            "vm_id": _canonical_uuid(vm_id, "vm_id", code=code),
            "role": _role(role, code=code),
        }
        for vm_id, role in approved_virtual_machines.items()
    ]
    ids = [item["vm_id"] for item in normalized]
    if len(ids) != len(set(ids)):
        raise InfrastructureValidationError(
            code, "approved VM identities must be unique."
        )
    return sorted(normalized, key=lambda item: item["vm_id"])


def _candidate_identity(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, Any] = {}
    for field in (
        "observation_id",
        "cell_id",
        "host_id",
        "agent_id",
        "agent_boot_id",
    ):
        raw = value.get(field)
        if isinstance(raw, str):
            try:
                result[field] = _canonical_uuid(
                    raw, field, code="invalid_observation"
                )
            except InfrastructureValidationError:
                pass
    sequence = value.get("sequence")
    if type(sequence) is int and 1 <= sequence <= MAX_SQLITE_INTEGER:
        result["sequence"] = sequence
    captured_at = value.get("captured_at")
    if isinstance(captured_at, str):
        try:
            result["captured_at"] = _canonical_utc(
                captured_at, "captured_at", code="invalid_observation"
            )
        except InfrastructureValidationError:
            pass
    return result


def _require_exact_fields(
    value: Any,
    required: set[str],
    *,
    code: str,
    subject: str,
) -> None:
    if not isinstance(value, Mapping):
        raise InfrastructureValidationError(code, f"{subject} must be a JSON object.")
    if set(value) != required:
        raise InfrastructureValidationError(
            code, f"{subject} fields do not match the closed v1 contract."
        )


def _canonical_uuid(value: Any, field: str, *, code: str) -> str:
    if not isinstance(value, str) or len(value) != 36:
        raise InfrastructureValidationError(
            code, f"{field} must be a canonical UUID."
        )
    try:
        canonical = str(uuid.UUID(value))
    except (ValueError, AttributeError):
        raise InfrastructureValidationError(
            code, f"{field} must be a canonical UUID."
        ) from None
    if canonical != value:
        raise InfrastructureValidationError(
            code, f"{field} must be a lowercase canonical UUID."
        )
    return canonical


def _bounded_string(
    value: Any,
    field: str,
    *,
    minimum: int,
    maximum: int,
    code: str,
) -> str:
    if (
        not isinstance(value, str)
        or not minimum <= len(value) <= maximum
        or value != value.strip()
        or unicodedata.normalize("NFC", value) != value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise InfrastructureValidationError(
            code, f"{field} is outside its bounded text contract."
        )
    return value


def _optional_bounded_string(
    value: Any,
    field: str,
    *,
    maximum: int,
    code: str,
) -> str | None:
    if value is None:
        return None
    return _bounded_string(
        value, field, minimum=1, maximum=maximum, code=code
    )


def _bounded_identifier(value: Any, field: str, *, code: str) -> str:
    text = _bounded_string(
        value, field, minimum=1, maximum=128, code=code
    )
    if not all(character.isalnum() or character in "_.:@-" for character in text):
        raise InfrastructureValidationError(
            code, f"{field} contains unsupported identifier characters."
        )
    return text


def _integer(
    value: Any,
    field: str,
    *,
    minimum: int,
    maximum: int,
    code: str,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise InfrastructureValidationError(
            code, f"{field} is outside its integer bound."
        )
    return value


def _sha256(value: Any, field: str, *, code: str) -> str:
    if not isinstance(value, str) or not _HEX_SHA256.fullmatch(value):
        raise InfrastructureValidationError(
            code, f"{field} must be 64 lowercase hexadecimal characters."
        )
    return value


def _role(value: Any, *, code: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _ROLE.fullmatch(value):
        raise InfrastructureValidationError(
            code, "role must be null or a bounded lowercase enrollment role."
        )
    return value


def _ip_list(value: Any, field: str, *, maximum: int) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise InfrastructureValidationError(
            "invalid_observation", f"{field} exceeds its array bound."
        )
    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str) or len(item) > 45:
            raise InfrastructureValidationError(
                "invalid_observation", f"{field} contains an invalid IP address."
            )
        try:
            canonical = str(ipaddress.ip_address(item))
        except ValueError:
            raise InfrastructureValidationError(
                "invalid_observation", f"{field} contains an invalid IP address."
            ) from None
        if canonical != item:
            raise InfrastructureValidationError(
                "invalid_observation",
                f"{field} IP addresses must use canonical text.",
            )
        if canonical in normalized:
            raise InfrastructureValidationError(
                "invalid_observation", f"{field} contains a duplicate IP address."
            )
        normalized.append(canonical)
    return sorted(normalized)


def _canonical_utc(value: Any, field: str, *, code: str) -> str:
    if not isinstance(value, str) or len(value) != 20 or not value.endswith("Z"):
        raise InfrastructureValidationError(
            code, f"{field} must be a second-resolution RFC3339 UTC timestamp."
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise InfrastructureValidationError(
            code, f"{field} must be a valid RFC3339 UTC timestamp."
        ) from None
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise InfrastructureValidationError(
            code, f"{field} must be UTC."
        )
    canonical = (
        parsed.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )
    if canonical != value:
        raise InfrastructureValidationError(
            code, f"{field} must use canonical second-resolution RFC3339 UTC text."
        )
    return value


def _parse_utc_epoch(value: str, field: str, *, code: str) -> int:
    canonical = _canonical_utc(value, field, code=code)
    return int(datetime.fromisoformat(canonical[:-1] + "+00:00").timestamp())


def _observation_freshness(
    value: str | None, *, now_epoch: int
) -> dict[str, Any]:
    if value is None:
        return {
            "status": "never",
            "age_seconds": None,
            "stale_after_seconds": OBSERVATION_STALE_AFTER_SECONDS,
        }
    observed_epoch = _parse_utc_epoch(
        str(value), "stored observation timestamp", code="stored_state_invalid"
    )
    age_seconds = max(0, int(now_epoch) - observed_epoch)
    return {
        "status": (
            "stale"
            if age_seconds >= OBSERVATION_STALE_AFTER_SECONDS
            else "fresh"
        ),
        "age_seconds": age_seconds,
        "stale_after_seconds": OBSERVATION_STALE_AFTER_SECONDS,
    }


def _detached_json(value: Any, *, code: str) -> Any:
    try:
        return json.loads(canonical_json(value))
    except (TypeError, ValueError, RecursionError) as error:
        raise InfrastructureValidationError(
            code, "Value must contain only bounded JSON data."
        ) from error


def _require_nfc_json_strings(value: Any) -> None:
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise InfrastructureValidationError(
                "noncanonical_unicode",
                "JWS payload strings must use NFC Unicode normalization.",
            )
        return
    if isinstance(value, list):
        for item in value:
            _require_nfc_json_strings(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _require_nfc_json_strings(key)
            _require_nfc_json_strings(item)


def _encoded_size(value: Any, *, code: str) -> int:
    try:
        return len(canonical_json(value).encode("utf-8"))
    except (TypeError, ValueError, RecursionError) as error:
        raise InfrastructureValidationError(
            code, "Value must contain only bounded JSON data."
        ) from error


def _json_string_list(value: Any) -> list[str]:
    try:
        decoded = json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise InfrastructureObservationError(
            "stored infrastructure address list is invalid"
        ) from error
    if not isinstance(decoded, list) or not all(
        isinstance(item, str) for item in decoded
    ):
        raise InfrastructureObservationError(
            "stored infrastructure address list is invalid"
        )
    return list(decoded)
