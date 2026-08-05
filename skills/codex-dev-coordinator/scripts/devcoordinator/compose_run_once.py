"""Sealed policy and receipt contracts for governed Compose one-shot work.

This module deliberately has no Docker or SQLite authority.  It normalizes the
administrator-authored manifest contract and validates one bounded stdout
receipt without ever returning unapproved raw process output.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import re
from types import MappingProxyType
from typing import Any, Mapping, Sequence


DEFAULT_COMPOSE_RUN_ONCE_TIMEOUT_SECONDS = 600
MAX_COMPOSE_RUN_ONCE_TIMEOUT_SECONDS = 3_600
MAX_COMPOSE_RUN_ONCE_SERVICES = 32
MAX_COMPOSE_RUN_ONCE_RECEIPT_BYTES = 64 * 1024
MAX_COMPOSE_RUN_ONCE_RECEIPT_FIELDS = 64
MAX_RECEIPT_STRING_BYTES = 8 * 1024
MAX_RECEIPT_ARRAY_ITEMS = 512

_SERVICE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_FIELD_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_RECEIPT_TYPES = frozenset(
    {
        "boolean",
        "boolean_or_null",
        "integer",
        "integer_or_null",
        "number",
        "number_or_null",
        "string",
        "string_or_null",
        "string_array",
        "string_array_or_null",
    }
)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _fingerprint(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value)).hexdigest()


def _receipt_field_mapping(value: Any, *, label: str) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, Mapping):
        raise ValueError(f"Compose run-once receipt {label} fields must be an object")
    if len(value) > MAX_COMPOSE_RUN_ONCE_RECEIPT_FIELDS:
        raise ValueError("Compose run-once receipt has too many declared fields")
    normalized: list[tuple[str, str]] = []
    for raw_name, raw_type in value.items():
        if not isinstance(raw_name, str) or _FIELD_NAME.fullmatch(raw_name) is None:
            raise ValueError("Compose run-once receipt contains an invalid field name")
        if not isinstance(raw_type, str) or raw_type not in _RECEIPT_TYPES:
            raise ValueError(
                "Compose run-once receipt field types must use the sealed type catalog"
            )
        normalized.append((raw_name, raw_type))
    return tuple(sorted(normalized))


@dataclass(frozen=True)
class ComposeRunOnceReceiptContract:
    """Allowlisted fields and exact primitive types for one stdout receipt."""

    required: tuple[tuple[str, str], ...]
    optional: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        required_input = tuple(self.required)
        optional_input = tuple(self.optional)
        if len({name for name, _field_type in required_input}) != len(
            required_input
        ) or len({name for name, _field_type in optional_input}) != len(
            optional_input
        ):
            raise ValueError("Compose run-once receipt fields must not repeat")
        required = _receipt_field_mapping(
            dict(required_input), label="required"
        )
        optional = _receipt_field_mapping(
            dict(optional_input), label="optional"
        )
        required_names = {name for name, _field_type in required}
        optional_names = {name for name, _field_type in optional}
        if not required:
            raise ValueError(
                "Compose run-once receipt requires at least one published field"
            )
        if required_names & optional_names:
            raise ValueError(
                "Compose run-once receipt fields cannot be both required and optional"
            )
        if len(required) + len(optional) > MAX_COMPOSE_RUN_ONCE_RECEIPT_FIELDS:
            raise ValueError("Compose run-once receipt has too many declared fields")
        object.__setattr__(self, "required", required)
        object.__setattr__(self, "optional", optional)

    @classmethod
    def from_document(cls, value: Any) -> "ComposeRunOnceReceiptContract":
        if not isinstance(value, Mapping) or not set(value) <= {
            "required",
            "optional",
        } or "required" not in value:
            raise ValueError(
                "Compose run-once receipt must contain required and optional field maps only"
            )
        return cls(
            required=_receipt_field_mapping(value["required"], label="required"),
            optional=_receipt_field_mapping(
                value.get("optional", {}), label="optional"
            ),
        )

    def to_document(self) -> dict[str, dict[str, str]]:
        return {
            "required": dict(self.required),
            "optional": dict(self.optional),
        }

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self.to_document())


@dataclass(frozen=True)
class ComposeRunOncePolicy:
    """One exact service capability sealed during root enrollment."""

    name: str
    max_timeout_seconds: int
    receipt: ComposeRunOnceReceiptContract

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or _SERVICE_NAME.fullmatch(self.name) is None:
            raise ValueError("Compose run-once service name is invalid")
        if (
            isinstance(self.max_timeout_seconds, bool)
            or not isinstance(self.max_timeout_seconds, int)
            or not DEFAULT_COMPOSE_RUN_ONCE_TIMEOUT_SECONDS
            <= self.max_timeout_seconds
            <= MAX_COMPOSE_RUN_ONCE_TIMEOUT_SECONDS
        ):
            raise ValueError(
                "Compose run-once max_timeout_seconds must be from 600 through 3600"
            )
        if not isinstance(self.receipt, ComposeRunOnceReceiptContract):
            raise TypeError("Compose run-once receipt policy is invalid")

    @classmethod
    def from_document(cls, value: Any) -> "ComposeRunOncePolicy":
        if not isinstance(value, Mapping) or set(value) != {
            "name",
            "max_timeout_seconds",
            "receipt",
        }:
            raise ValueError(
                "Compose run-once service requires name, max_timeout_seconds, and receipt"
            )
        return cls(
            name=value["name"],
            max_timeout_seconds=value["max_timeout_seconds"],
            receipt=ComposeRunOnceReceiptContract.from_document(value["receipt"]),
        )

    def to_document(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "max_timeout_seconds": self.max_timeout_seconds,
            "receipt": self.receipt.to_document(),
        }

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self.to_document())


def normalize_compose_run_once_policies(
    value: Any,
) -> tuple[ComposeRunOncePolicy, ...]:
    """Normalize an administrator-authored bounded service-policy sequence."""

    if value is None or value == ():
        return ()
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise ValueError("docker.run_once_services must be an array of objects")
    if len(value) > MAX_COMPOSE_RUN_ONCE_SERVICES:
        raise ValueError("docker.run_once_services contains too many services")
    policies = tuple(ComposeRunOncePolicy.from_document(item) for item in value)
    names = tuple(policy.name for policy in policies)
    if len(set(names)) != len(names):
        raise ValueError("docker.run_once_services contains duplicate service names")
    return tuple(sorted(policies, key=lambda item: item.name))


def compose_run_once_policies_document(
    policies: Sequence[ComposeRunOncePolicy],
) -> list[dict[str, Any]]:
    normalized = normalize_compose_run_once_policies(
        [policy.to_document() for policy in policies]
    )
    return [policy.to_document() for policy in normalized]


@dataclass(frozen=True)
class PublishedReceipt:
    """Only allowlisted, type-checked receipt data safe for a broker reply."""

    status: str
    receipt: Mapping[str, Any] | None
    receipt_sha256: str | None
    error_code: str | None

    def __post_init__(self) -> None:
        if self.status not in {
            "valid",
            "empty",
            "too_large",
            "invalid_utf8",
            "invalid_json",
            "invalid_shape",
            "invalid_fields",
            "invalid_types",
        }:
            raise ValueError("receipt status is invalid")
        if self.status == "valid":
            if (
                not isinstance(self.receipt, Mapping)
                or not isinstance(self.receipt_sha256, str)
                or _SHA256.fullmatch(self.receipt_sha256) is None
                or self.error_code is not None
            ):
                raise ValueError("valid receipt evidence is incomplete")
        elif (
            self.receipt is not None
            or self.receipt_sha256 is not None
            or not isinstance(self.error_code, str)
        ):
            raise ValueError("invalid receipt evidence must remain categorical")


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"unsupported JSON constant: {value}")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object field")
        result[key] = value
    return result


def _receipt_value_matches(value: Any, field_type: str) -> bool:
    nullable = field_type.endswith("_or_null")
    if value is None:
        return nullable
    base = field_type.removesuffix("_or_null")
    if base == "boolean":
        return type(value) is bool
    if base == "integer":
        return type(value) is int
    if base == "number":
        return (
            type(value) in {int, float}
            and not isinstance(value, bool)
            and (type(value) is int or math.isfinite(value))
        )
    if base == "string":
        return (
            isinstance(value, str)
            and "\x00" not in value
            and len(value.encode("utf-8")) <= MAX_RECEIPT_STRING_BYTES
        )
    if base == "string_array":
        return (
            isinstance(value, list)
            and len(value) <= MAX_RECEIPT_ARRAY_ITEMS
            and all(
                isinstance(item, str)
                and "\x00" not in item
                and len(item.encode("utf-8")) <= MAX_RECEIPT_STRING_BYTES
                for item in value
            )
        )
    return False


def validate_published_receipt(
    payload: bytes,
    *,
    contract: ComposeRunOnceReceiptContract,
    truncated: bool = False,
) -> PublishedReceipt:
    """Validate exactly one JSON object and publish only declared fields.

    The caller separately hashes and counts the raw process streams.  This
    function never includes rejected raw text, unexpected fields, or parser
    diagnostics in its result.
    """

    if not isinstance(payload, bytes):
        raise TypeError("Compose run-once receipt payload must be bytes")
    if not isinstance(contract, ComposeRunOnceReceiptContract):
        raise TypeError("Compose run-once receipt contract is invalid")
    if type(truncated) is not bool:
        raise TypeError("Compose run-once receipt truncation flag must be boolean")
    if truncated or len(payload) > MAX_COMPOSE_RUN_ONCE_RECEIPT_BYTES:
        return PublishedReceipt("too_large", None, None, "receipt_too_large")
    if not payload:
        return PublishedReceipt("empty", None, None, "receipt_empty")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return PublishedReceipt("invalid_utf8", None, None, "receipt_invalid_utf8")
    if "\x00" in text:
        return PublishedReceipt("invalid_utf8", None, None, "receipt_invalid_utf8")
    decoder = json.JSONDecoder(
        object_pairs_hook=_unique_json_object,
        parse_constant=_reject_json_constant,
    )
    start = 0
    while start < len(text) and text[start].isspace():
        start += 1
    if start == len(text):
        return PublishedReceipt("empty", None, None, "receipt_empty")
    try:
        value, end = decoder.raw_decode(text, start)
    except (ValueError, json.JSONDecodeError):
        return PublishedReceipt("invalid_json", None, None, "receipt_invalid_json")
    if text[end:].strip():
        return PublishedReceipt("invalid_json", None, None, "receipt_trailing_data")
    if not isinstance(value, dict):
        return PublishedReceipt("invalid_shape", None, None, "receipt_not_object")
    required = dict(contract.required)
    optional = dict(contract.optional)
    allowed = set(required) | set(optional)
    if not set(required) <= set(value) or not set(value) <= allowed:
        return PublishedReceipt(
            "invalid_fields", None, None, "receipt_fields_invalid"
        )
    field_types = {**required, **optional}
    if any(
        not _receipt_value_matches(field_value, field_types[field_name])
        for field_name, field_value in value.items()
    ):
        return PublishedReceipt(
            "invalid_types", None, None, "receipt_types_invalid"
        )
    published = {
        name: value[name]
        for name in sorted(value)
    }
    digest = _fingerprint(published)
    return PublishedReceipt(
        "valid",
        MappingProxyType(published),
        digest,
        None,
    )


__all__ = [
    "ComposeRunOncePolicy",
    "ComposeRunOnceReceiptContract",
    "DEFAULT_COMPOSE_RUN_ONCE_TIMEOUT_SECONDS",
    "MAX_COMPOSE_RUN_ONCE_RECEIPT_BYTES",
    "MAX_COMPOSE_RUN_ONCE_TIMEOUT_SECONDS",
    "PublishedReceipt",
    "compose_run_once_policies_document",
    "normalize_compose_run_once_policies",
    "validate_published_receipt",
]
