"""Administrator-sealed capabilities for repository test attempts.

Repository manifests may request fixture and network behavior, but they never
grant it.  The root authority loads one immutable, private policy document at
startup and clamps every launch descriptor to its exact repository generation.
An absent policy is a valid default-deny configuration.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from typing import Mapping

from .universal_test_runtime import TestAttemptDescriptor
from .universal_test_store import TestStoreConflict, TestStoreContractError


DEFAULT_TEST_CAPABILITY_PATH = Path(
    "/etc/devcoordinator/test-execution-capabilities.json"
)
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")
_CAPABILITY = re.compile(
    r"^(?:network\.(?:loopback|host-loopback|external)|fixture\.[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}|credential\.[a-z][a-z0-9_.-]{0,127})$"
)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


@dataclass(frozen=True)
class RepositoryTestCapabilities:
    generation: int
    capabilities: frozenset[str]


class SealedTestCapabilityRegistry:
    """Fail-closed repository-generation policy loaded by root authority."""

    def __init__(
        self,
        repositories: Mapping[str, RepositoryTestCapabilities] = (),
        *,
        policy_fingerprint: str | None = None,
    ) -> None:
        normalized = dict(repositories)
        if any(
            not isinstance(repo_id, str)
            or _SAFE_ID.fullmatch(repo_id) is None
            or not isinstance(entry, RepositoryTestCapabilities)
            for repo_id, entry in normalized.items()
        ):
            raise TestStoreContractError("test capability registry is invalid")
        self.repositories = MappingProxyType(dict(sorted(normalized.items())))
        self.policy_fingerprint = policy_fingerprint or hashlib.sha256(
            _canonical_json({"schema_version": 1, "repositories": []})
        ).hexdigest()

    @classmethod
    def load(
        cls,
        path: Path = DEFAULT_TEST_CAPABILITY_PATH,
        *,
        expected_uid: int = 0,
        allow_missing: bool = True,
    ) -> "SealedTestCapabilityRegistry":
        path = Path(path)
        if not path.is_absolute():
            raise TestStoreContractError("test capability path must be absolute")
        try:
            metadata = path.lstat()
            resolved = path.resolve(strict=True)
        except FileNotFoundError:
            if allow_missing:
                return cls()
            raise TestStoreConflict("sealed test capability policy is missing") from None
        except OSError as error:
            raise TestStoreConflict("sealed test capability policy is unavailable") from error
        # On this single-developer host, Unix ownership and mode are not
        # authorization signals. ``expected_uid`` is retained only for API
        # compatibility; exact path/type, bounded content, and schema remain.
        del expected_uid
        if (
            resolved != path
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > 1024 * 1024
        ):
            raise TestStoreConflict("sealed test capability policy is unsafe")
        try:
            payload = path.read_bytes()
            raw = json.loads(payload)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise TestStoreContractError("sealed test capability policy is invalid") from error
        if (
            not isinstance(raw, Mapping)
            or set(raw) != {"schema_version", "repositories"}
            or raw["schema_version"] != 1
            or not isinstance(raw["repositories"], list)
            or len(raw["repositories"]) > 10_000
        ):
            raise TestStoreContractError("sealed test capability policy fields are invalid")
        repositories: dict[str, RepositoryTestCapabilities] = {}
        for item in raw["repositories"]:
            if (
                not isinstance(item, Mapping)
                or set(item) != {"repository_id", "generation", "capabilities"}
                or not isinstance(item["repository_id"], str)
                or _SAFE_ID.fullmatch(item["repository_id"]) is None
                or type(item["generation"]) is not int
                or item["generation"] < 0
                or not isinstance(item["capabilities"], list)
                or len(item["capabilities"]) > 128
                or any(
                    not isinstance(capability, str)
                    or _CAPABILITY.fullmatch(capability) is None
                    for capability in item["capabilities"]
                )
                or len(set(item["capabilities"])) != len(item["capabilities"])
                or item["repository_id"] in repositories
            ):
                raise TestStoreContractError(
                    "sealed test capability repository entry is invalid"
                )
            repositories[item["repository_id"]] = RepositoryTestCapabilities(
                generation=item["generation"],
                capabilities=frozenset(item["capabilities"]),
            )
        return cls(
            repositories,
            policy_fingerprint=hashlib.sha256(_canonical_json(raw)).hexdigest(),
        )

    def authorize(self, descriptor: TestAttemptDescriptor) -> str:
        """Authorize one sensitive attempt or fail closed.

        Every attempt requires an exact repository-generation grant.  Network
        and fixture requests additionally require fixed named capabilities;
        the manifest alone can never grant access.
        """

        requested = set()
        if descriptor.network != "none":
            requested.add(f"network.{descriptor.network}")
        requested.update(f"fixture.{name}" for name in descriptor.fixtures)
        requested.update(f"credential.{name}" for name in descriptor.credentials)
        entry = self.repositories.get(descriptor.repository_id)
        if entry is None or entry.generation != descriptor.repository_generation:
            raise TestStoreConflict(
                "test attempt has no sealed capability for this repository generation"
            )
        missing = sorted(requested - entry.capabilities)
        if missing:
            raise TestStoreConflict(
                "test attempt capability is not administrator-approved: "
                + ", ".join(missing)
            )
        return self.policy_fingerprint

    def check_requests(
        self,
        *,
        repository_id: str,
        repository_generation: int,
        networks: tuple[str, ...] = (),
        fixtures: tuple[str, ...] = (),
        credentials: tuple[str, ...] = (),
    ) -> Mapping[str, object]:
        """Return a path- and secret-free preflight for declared capabilities."""

        if (
            not isinstance(repository_id, str)
            or _SAFE_ID.fullmatch(repository_id) is None
            or type(repository_generation) is not int
            or repository_generation < 0
        ):
            raise TestStoreContractError("test capability preflight identity is invalid")
        requested = {
            f"network.{network}"
            for network in networks
            if network != "none"
        }
        requested.update(f"fixture.{name}" for name in fixtures)
        requested.update(f"credential.{name}" for name in credentials)
        if any(_CAPABILITY.fullmatch(item) is None for item in requested):
            raise TestStoreContractError("test capability preflight request is invalid")
        entry = self.repositories.get(repository_id)
        generation_match = (
            entry is not None and entry.generation == repository_generation
        )
        granted = entry.capabilities if generation_match and entry is not None else frozenset()
        missing = sorted(requested - granted)
        if not generation_match:
            missing.insert(0, "repository-generation-grant")
        return MappingProxyType(
            {
                "ok": not missing,
                "policy_fingerprint": self.policy_fingerprint,
                "repository_generation": repository_generation,
                "requested": sorted(requested),
                "missing": missing,
                "repository_grant": entry is not None,
                "generation_match": generation_match,
            }
        )


__all__ = [
    "DEFAULT_TEST_CAPABILITY_PATH",
    "RepositoryTestCapabilities",
    "SealedTestCapabilityRegistry",
]
