#!/usr/bin/python3
"""Root-only operational credential administration for universal tests.

The command line carries only an exact source path, dotenv key name, and
non-secret binding metadata.  Credential bytes are read through a no-follow
file descriptor and never printed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
MODULE_ROOT = ROOT / "skills" / "codex-dev-coordinator" / "scripts"
sys.path.insert(0, str(MODULE_ROOT))

from devcoordinator.universal_test_credentials import (  # noqa: E402
    AdministratorOperationalCredentialStore,
    DEFAULT_TEST_CREDENTIAL_MATERIAL_ROOT,
    DEFAULT_TEST_CREDENTIAL_REGISTRY_PATH,
    public_binding_document,
)


def _positive(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def _nonnegative(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage broker-owned universal-test operational credentials."
    )
    parser.add_argument(
        "--registry",
        type=Path,
        default=DEFAULT_TEST_CREDENTIAL_REGISTRY_PATH,
    )
    parser.add_argument(
        "--material-root",
        type=Path,
        default=DEFAULT_TEST_CREDENTIAL_MATERIAL_ROOT,
    )
    actions = parser.add_subparsers(dest="action", required=True)

    register = actions.add_parser("register")
    register.add_argument("--alias", required=True)
    register.add_argument("--repository-id", required=True)
    register.add_argument("--repository-generation", type=_nonnegative, required=True)
    register.add_argument("--target", required=True)
    register.add_argument("--intent", choices=("manual",), default="manual")
    register.add_argument("--owner-uid", type=_positive, required=True)
    register.add_argument("--credential-name", required=True)
    register.add_argument("--max-ttl-seconds", type=_positive, required=True)
    register.add_argument("--source-env-file", type=Path, required=True)
    register.add_argument("--source-key", required=True)
    register.add_argument("--source-uid", type=_nonnegative)

    rotate = actions.add_parser("rotate")
    rotate.add_argument("--alias", required=True)
    rotate.add_argument(
        "--expected-rotation-generation", type=_positive, required=True
    )
    rotate.add_argument("--source-env-file", type=Path, required=True)
    rotate.add_argument("--source-key", required=True)
    rotate.add_argument("--source-uid", type=_nonnegative)

    revoke = actions.add_parser("revoke")
    revoke.add_argument("--alias", required=True)
    revoke.add_argument(
        "--expected-rotation-generation", type=_positive, required=True
    )

    actions.add_parser("list")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    store = AdministratorOperationalCredentialStore(
        registry_path=arguments.registry,
        material_root=arguments.material_root,
    )
    if arguments.action == "register":
        source_uid = (
            arguments.owner_uid
            if arguments.source_uid is None
            else arguments.source_uid
        )
        binding = store.register(
            alias=arguments.alias,
            repository_id=arguments.repository_id,
            repository_generation=arguments.repository_generation,
            target_name=arguments.target,
            intent=arguments.intent,
            owner_uid=arguments.owner_uid,
            credential_name=arguments.credential_name,
            max_ttl_seconds=arguments.max_ttl_seconds,
            source_path=arguments.source_env_file,
            source_key=arguments.source_key,
            source_uid=source_uid,
        )
        result: object = dict(public_binding_document(binding))
    elif arguments.action == "rotate":
        registry = store.load(allow_missing=False)
        existing = registry.bindings.get(arguments.alias)
        if existing is None:
            raise SystemExit("credential binding alias is unknown")
        source_uid = (
            existing.owner_uid
            if arguments.source_uid is None
            else arguments.source_uid
        )
        binding = store.rotate(
            alias=arguments.alias,
            expected_rotation_generation=arguments.expected_rotation_generation,
            source_path=arguments.source_env_file,
            source_key=arguments.source_key,
            source_uid=source_uid,
        )
        result = dict(public_binding_document(binding))
    elif arguments.action == "revoke":
        binding = store.revoke(
            alias=arguments.alias,
            expected_rotation_generation=arguments.expected_rotation_generation,
        )
        result = dict(public_binding_document(binding))
    else:
        registry = store.load(allow_missing=True)
        result = {
            "schema_version": 1,
            "authority_generation": registry.authority_generation,
            "bindings": [
                dict(public_binding_document(binding))
                for binding in registry.bindings.values()
            ],
        }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
