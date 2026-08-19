#!/usr/bin/env python3
"""Focused tests for credential-safe, reversible availability activation."""

from __future__ import annotations

import argparse
from contextlib import closing, redirect_stderr, redirect_stdout
import http.client
import io
import json
import hashlib
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
from typing import Mapping
import unittest
from unittest import mock
import uuid


ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "scripts", ROOT / "skills/codex-dev-coordinator/scripts"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import activate_availability_release as activation  # noqa: E402
import dev_coordinator  # noqa: E402
import manage_universal_test_adoption as adoption_cli  # noqa: E402
import orchestrate_availability_cutover as cutover  # noqa: E402
import self_test_orchestrate_availability_cutover as fixtures  # noqa: E402
from devcoordinator.inventory_projection import (  # noqa: E402
    envelope as inventory_envelope,
    initialize_inventory_store,
    publish_projection,
)
from devcoordinator.broker import (  # noqa: E402
    BrokerClient,
    BrokerOperation,
    BrokerRequest,
)
from devcoordinator.maintenance import (  # noqa: E402
    CONTROL_PLANE_MAINTENANCE_SCOPE,
    PUBLIC_MAINTENANCE_MESSAGE,
    activate_maintenance,
)


DIGEST = fixtures.RELEASE
OLD_DIGEST = "b" * 64
FIRST_ADOPTION_PORTS = {
    "console_outer": 31443,
    "console_inner": 31444,
    "handoff_http": 38080,
    "handoff_https": 38443,
    "handoff_api": 39876,
}


def private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path


def private_file(path: Path, payload: bytes, mode: int = 0o600) -> Path:
    private_dir(path.parent)
    path.write_bytes(payload)
    path.chmod(mode)
    return path


def console_slot_payload(release_digest: str = DIGEST) -> bytes:
    return (
        f"DEVCOORDINATOR_RELEASE_DIGEST={release_digest}\n"
        f"HTTPS_PORT={FIRST_ADOPTION_PORTS['console_outer']}\n"
        "DEVCOORDINATOR_CONSOLE_INNER_PORT="
        f"{FIRST_ADOPTION_PORTS['console_inner']}\n"
    ).encode()


def first_adoption_port_request(
    root: Path,
    *,
    digest: str = "a" * 64,
    reservations: Mapping[str, int] | None = None,
) -> dict[str, object]:
    return {
        "bundle": str(root / "port-reservations.json"),
        "sha256": digest,
        "reservations": dict(reservations or FIRST_ADOPTION_PORTS),
    }


def first_adoption_port_bundle(
    root: Path,
    *,
    release_digest: str = DIGEST,
    authority_database: str,
    document_sha256: str | None = None,
    reservations: Mapping[str, int] | None = None,
) -> dict[str, object]:
    ports = dict(reservations or FIRST_ADOPTION_PORTS)
    operation_id = str(uuid.uuid4())
    payload = {
        "operation_id": operation_id,
        "release_digest": release_digest,
        "authority_database": authority_database,
        "authority_generation": fixtures.AUTHORITY_GENERATION,
        "authority_state_revision_before": 40,
        "authority_state_revision_after": 41,
        "repository_id": "repo-alpha",
        "repository_generation": 7,
        "canonical_root": str(ROOT),
        "port_range": dict(cutover.FIRST_ADOPTION_PORT_RANGE),
        "handoff_ttl_seconds": 3600,
        "reservations": {
            role: {
                "lease_id": str(uuid.uuid4()),
                "port": port,
                "agent": cutover._first_adoption_port_agent(operation_id),
                "purpose": cutover._first_adoption_port_purpose(
                    release_digest, role
                ),
                "status": "active",
                "expires_at": (
                    None
                    if role in cutover.FIRST_ADOPTION_CONSOLE_PORT_ROLES
                    else "2026-07-29T01:00:00.000Z"
                ),
            }
            for role, port in ports.items()
        },
        "transaction_journal_sha256": "b" * 64,
        "service_unit": "devcoordinator-broker.service",
        "service_restored": True,
        "maintenance_cleared": True,
        "created_at": "2026-07-29T00:00:00.000Z",
        "completed_at": "2026-07-29T00:00:01.000Z",
    }
    bundle = cutover.seal(
        cutover.FIRST_ADOPTION_PORT_RESERVATIONS_KIND,
        payload,
    )
    if document_sha256 is not None:
        bundle["document_sha256"] = document_sha256
    return bundle


def oidc(_url: str, _timeout: float) -> bytes:
    return json.dumps(
        {
            "issuer": activation.OIDC_ISSUER,
            "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_endpoint": "https://oauth2.googleapis.com/token",
            "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
        }
    ).encode()


def candidate_state(release: Path) -> dict[str, object]:
    state, _authority, _testd = fixtures.through_seal(release=release)
    state = cutover.transition(
        state,
        evidence_kind="profile-inventory-readiness",
        evidence=fixtures.profile_inventory_readiness(release=release),
    )
    candidate = fixtures.candidate(release=release)
    preparation = candidate["preparation"]
    preparation = cutover.seal(
        cutover.CANDIDATE_PREPARATION_KIND,
        {
            key: value
            for key, value in preparation.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        | {
            "console_slot_ports": {
                "console_outer": 31443,
                "console_inner": 32443,
            }
        },
    )
    candidate = cutover.seal(
        cutover.CANDIDATE_KIND,
        {
            key: value
            for key, value in candidate.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        | {
            "preparation": preparation,
            "migration_seal_sha256": state["evidence"]["test-history-discard"][
                "document_sha256"
            ]
        },
    )
    state = cutover.transition(state, evidence_kind="candidate", evidence=candidate)
    return state


def credential_files(root: Path) -> dict[str, Path]:
    return {
        "session-secret": private_file(root / "edge/session", b"a" * 64 + b"\n"),
        "oidc-client-id": private_file(
            root / "edge/client-id",
            b"123456789-test.apps.googleusercontent.com\n",
        ),
        "oidc-client-secret": private_file(root / "edge/client-secret", b"client-secret-value\n"),
        "tls-cert": private_file(root / "tls/fullchain.pem", b"certificate\n", 0o600),
        "tls-key": private_file(root / "tls/privkey.pem", b"private-key\n"),
    }


def publication(path: Path) -> dict[str, object]:
    envelope = {
        "schema_version": 1,
        "payload_sha256": "d" * 64,
        "publication": {
            "schema_version": 1,
            "generation": 7,
            "published_at": "2026-07-28T00:00:00.000Z",
            "domain": "vr.ae",
            "console_host": "console.vr.ae",
            "release_digest": OLD_DIGEST,
            "maintenance": {"active": False, "deployment_id": None, "retry_after_seconds": 0, "started_at": None},
            "session": {"cookie_name": "session"},
            "access": {},
            "routes": {"sample": {}},
            "console": {
                "asset_root": f"/opt/devcoordinator/releases/{OLD_DIGEST}/apps/DevOpsConsole/src/ui",
                "upstream": {
                    "host": "127.0.0.1",
                    "port": 30443,
                    "scheme": "https",
                    "tls_server_name": "console.vr.ae",
                    "tls_verify": True,
                },
            },
        },
    }
    envelope["payload_sha256"] = activation._sha256_bytes(
        activation._canonical(envelope["publication"])
    )
    private_file(path, json.dumps(envelope).encode())
    return envelope


class FakeRunner:
    def __init__(self, publication_file: Path, events: list[str]) -> None:
        self.publication_file = publication_file
        self.events = events
        self.modes = {"/candidate.sock": "standby", "/previous.sock": "active"}
        self.mutation_count = 0

    def run_json(self, argv):
        argv = list(argv)
        self.events.append("command:" + Path(argv[0]).name + ":" + argv[1])
        if Path(argv[0]).name == "devcoordinator-edge-publication":
            current = json.loads(self.publication_file.read_text())
            if argv[1] == "verify":
                return {
                    "ok": True,
                    "payload_sha256": current["payload_sha256"],
                    "generation": current["publication"]["generation"],
                    "release_digest": current["publication"]["release_digest"],
                }
            expected = argv[argv.index("--expected-payload-sha256") + 1]
            if expected != current["payload_sha256"]:
                raise activation.ActivationError("stale publication")
            release = argv[argv.index("--release-digest") + 1]
            port = int(argv[argv.index("--port") + 1])
            old_hash = current["payload_sha256"]
            old_generation = current["publication"]["generation"]
            current["publication"]["generation"] += 1
            current["publication"]["published_at"] = argv[
                argv.index("--published-at") + 1
            ]
            current["publication"]["release_digest"] = release
            current["publication"]["console"]["asset_root"] = (
                f"{self.publication_file.parent.parent}/releases/{release}/apps/DevOpsConsole/src/ui"
            )
            current["publication"]["console"]["upstream"]["port"] = port
            new_hash = activation._sha256_bytes(
                activation._canonical(current["publication"])
            )
            current["payload_sha256"] = new_hash
            self.publication_file.write_text(json.dumps(current))
            self.publication_file.chmod(0o600)
            self.mutation_count += 1
            return {
                "ok": True,
                "previous_generation": old_generation,
                "generation": old_generation + 1,
                "previous_payload_sha256": old_hash,
                "payload_sha256": new_hash,
                "release_digest": release,
                "port": port,
            }
        operation = argv[1]
        control = argv[argv.index("--socket") + 1]
        if operation == "status":
            release = DIGEST if control == "/candidate.sock" else OLD_DIGEST
            port = 31443 if control == "/candidate.sock" else 30443
            return {
                "ok": True,
                "mode": self.modes[control],
                "release_digest": release,
                "port": port,
            }
        if operation == "promote":
            old = argv[argv.index("--old-socket") + 1]
            self.modes[control] = "active"
            self.modes[old] = "standby"
            self.mutation_count += 1
            return {"ok": True, "mode": "active"}
        raise AssertionError(argv)

    def status(self, argv):
        self.events.append("systemctl:" + ":".join(argv[1:]))
        if argv[1] == "is-active":
            return 3
        if argv[1] == "is-enabled":
            return 1
        return 0

    def text(self, argv):
        raise AssertionError(argv)


class PrepareRunner:
    def __init__(
        self,
        unit_root: Path,
        *,
        host_preflight: Mapping[str, object],
        fail_enable_at: int | None = None,
    ) -> None:
        self.unit_root = unit_root
        self.host_preflight = dict(host_preflight)
        self.fail_enable_at = fail_enable_at
        self.enable_count = 0
        self.commands: list[tuple[str, ...]] = []
        self.background_transactions: dict[str, dict[str, object]] = {}
        self.isolation_source_schema_version = 15

    def run_json(self, argv):
        self.commands.append(tuple(argv))
        executable = Path(argv[0]).name
        if executable == "devcoordinator-test-preflight" and list(argv[1:]) == ["--json"]:
            return dict(self.host_preflight)
        if executable == "devcoordinator-background-handoff":
            if argv[1] == "render":
                directory = Path(argv[argv.index("--output-directory") + 1])
                project = argv[argv.index("--project-root") + 1]
                directory.mkdir(mode=0o700)
                files = {
                    "notifications.env": "sha256:" + "1" * 64,
                    "observer.env": "sha256:" + "2" * 64,
                }
                for name in files:
                    private_file(directory / name, f"{name}=fixture\n".encode(), 0o400)
                private_file(directory / "transaction.json", b'{"fixture":true}\n', 0o400)
                self.background_transactions[str(directory)] = {
                    "ok": True,
                    "kind": activation.BACKGROUND_CONFIG_KIND,
                    "directory": str(directory),
                    "project_root": project,
                    "files": files,
                    "administrator_count": 1,
                }
            if argv[1] == "verify-config":
                directory = argv[argv.index("--directory") + 1]
                return dict(self.background_transactions[directory])
            directory = argv[argv.index("--output-directory") + 1]
            return dict(self.background_transactions[directory])
        if executable == "devcoordinator-project-isolation-audit":
            if argv[1] == "capture":
                self.isolation_source_schema_version = 15
                output = Path(argv[argv.index("--output") + 1])
                private_file(output, b'{"fixture":"isolation"}\n', 0o400)
                return {
                    "ok": True,
                    "kind": "project-runtime-isolation-audit",
                    "output": str(output),
                    "evidence_sha256": "sha256:" + "8" * 64,
                    "counts": {
                        "compliant": 1,
                        "legacy_requires_recreation": 0,
                        "unobservable": 0,
                    },
                    "project_isolation_complete": True,
                    "valid_until": activation._now(),
                }
            if argv[1] == "verify":
                return {
                    "ok": True,
                    "kind": activation.PROJECT_ISOLATION_VERIFICATION_KIND,
                    "audit_sha256": "sha256:" + "8" * 64,
                    "source_schema_version": self.isolation_source_schema_version,
                    "audit_counts": {
                        "compliant": 1,
                        "legacy_requires_recreation": 0,
                        "unobservable": 0,
                    },
                    "project_isolation_complete": True,
                }
            raise AssertionError(argv)
        raise AssertionError(argv)

    def status(self, argv):
        argv = tuple(argv)
        self.commands.append(argv)
        if len(argv) > 2 and argv[1] == "is-active":
            return 3
        if len(argv) > 2 and argv[1] == "is-enabled":
            return 1
        if len(argv) > 2 and argv[1] == "enable" and "--now" in argv:
            self.enable_count += 1
            if self.fail_enable_at == self.enable_count:
                return 1
        return 0

    def text(self, argv):
        unit = argv[2]
        if unit.startswith("devcoordinator-console@"):
            uid, slice_name, fragment = 2303, cutover.CONTROL_SLICE, "devcoordinator-console@.service"
        else:
            mapping = {
                "devcoordinator-edge.service": (2301, cutover.CONTROL_SLICE),
                "devcoordinator-api.service": (fixtures.API_UID, cutover.CONTROL_SLICE),
                "devcoordinator-authority.service": (0, cutover.CONTROL_SLICE),
                "devcoordinator-observer.service": (2304, cutover.BACKGROUND_SLICE),
                "devcoordinator-testd.service": (fixtures.TESTD_UID, cutover.BACKGROUND_SLICE),
                "devcoordinator-test-snapshotd.service": (0, cutover.BACKGROUND_SLICE),
            }
            uid, slice_name = mapping[unit]
            fragment = unit
        return (
            "ActiveState=active\n"
            f"UID={uid}\n"
            f"Slice={slice_name}\n"
            f"FragmentPath={self.unit_root / fragment}\n"
        )


class FirewallRunner:
    def text(self, argv):
        if Path(argv[0]).name.endswith("save"):
            return "*nat\nCOMMIT\n"
        return "iptables v1.8.11 (nf_tables)\n"

    def status(self, argv):
        return 0


class ApiFirewallRunner:
    def __init__(self) -> None:
        self.chain = False
        self.rules: set[tuple[str, ...]] = set()
        self.systemd: list[tuple[str, ...]] = []
        self.legacy_api_active = True
        self.legacy_api_enabled = True
        self.unit_states: dict[str, list[bool]] = {}

    @staticmethod
    def _normalized(rule):
        value = list(rule)
        if value and value[0] in {"-A", "-I", "-C", "-D"}:
            value[0] = "-A"
        if len(value) > 2 and value[2] == "1":
            del value[2]
        return tuple(value)

    def text(self, argv):
        if Path(argv[0]).name == "iptables-save":
            private_rows = [
                f"{activation.API_HANDOFF_CHAIN} {' '.join(rule)}"
                for rule in sorted(self.rules)
            ]
            return "\n".join(
                ["*nat", "-A FOREIGN -j ACCEPT", *private_rows, "COMMIT", ""]
            )
        raise AssertionError(argv)

    def status(self, argv):
        argv = list(argv)
        if argv[0] == "/usr/bin/systemctl":
            self.systemd.append(tuple(argv[1:]))
            unit = argv[-1]
            if unit == activation.LEGACY_API_SERVICE_UNIT:
                state = [
                    self.legacy_api_active,
                    self.legacy_api_enabled,
                ]
            else:
                state = self.unit_states.setdefault(
                    unit, [False, False]
                )
            if argv[1:3] == ["is-active", "--quiet"]:
                return 0 if state[0] else 1
            if argv[1:3] == ["is-enabled", "--quiet"]:
                return 0 if state[1] else 1
            if argv[1] == "disable":
                state[1] = False
                if "--now" in argv:
                    state[0] = False
            if argv[1] == "enable":
                state[1] = True
                if "--now" in argv:
                    state[0] = True
            if argv[1] == "start":
                state[0] = True
            if argv[1] == "stop":
                state[0] = False
            if argv[1:4] == [
                "disable",
                "--now",
                activation.LEGACY_API_SERVICE_UNIT,
            ]:
                self.legacy_api_active = False
                self.legacy_api_enabled = False
            if argv[1:3] == [
                "start",
                activation.LEGACY_API_SERVICE_UNIT,
            ]:
                self.legacy_api_active = True
            if argv[1:3] == [
                "enable",
                activation.LEGACY_API_SERVICE_UNIT,
            ]:
                self.legacy_api_enabled = True
            if argv[1:4] == [
                "enable",
                "--now",
                activation.LEGACY_API_SERVICE_UNIT,
            ]:
                self.legacy_api_active = True
                self.legacy_api_enabled = True
            if unit != activation.LEGACY_API_SERVICE_UNIT:
                self.unit_states[unit] = state
            return 0
        arguments = argv[argv.index("nat") + 1 :]
        operation = arguments[0]
        if operation == "-S":
            return 0 if self.chain else 1
        if operation == "-N":
            self.chain = True
            return 0
        if operation in {"-A", "-I"}:
            self.rules.add(self._normalized(arguments))
            return 0
        if operation == "-C":
            return 0 if self._normalized(arguments) in self.rules else 1
        if operation == "-D":
            self.rules.discard(self._normalized(arguments))
            return 0
        if operation == "-F":
            self.rules.clear()
            return 0
        if operation == "-X":
            self.chain = False
            return 0
        raise AssertionError(argv)


class EdgeFirewallRunner:
    def __init__(self) -> None:
        self.chains = {"ipv4": False, "ipv6": False}
        self.rules: dict[str, set[tuple[str, ...]]] = {
            "ipv4": set(),
            "ipv6": set(),
        }

    @staticmethod
    def _family(argv) -> str:
        return "ipv6" if Path(argv[0]).name.startswith("ip6") else "ipv4"

    @staticmethod
    def _normalized(rule):
        value = list(rule)
        if value and value[0] in {"-A", "-I", "-C", "-D"}:
            value[0] = "-A"
        if len(value) > 2 and value[2] == "1":
            del value[2]
        return tuple(value)

    def text(self, argv):
        family = self._family(argv)
        if Path(argv[0]).name.endswith("save"):
            private_rows = [
                " ".join(rule) for rule in sorted(self.rules[family])
            ]
            declaration = (
                [f":{activation.HANDOFF_CHAIN} - [0:0]"]
                if self.chains[family]
                else []
            )
            return "\n".join(
                ["*nat", "-A FOREIGN -j ACCEPT", *declaration, *private_rows, "COMMIT", ""]
            )
        raise AssertionError(argv)

    def status(self, argv):
        argv = list(argv)
        family = self._family(argv)
        arguments = argv[argv.index("nat") + 1 :]
        operation = arguments[0]
        if operation == "-S":
            return 0 if self.chains[family] else 1
        if operation == "-N":
            self.chains[family] = True
            return 0
        if operation in {"-A", "-I"}:
            self.rules[family].add(self._normalized(arguments))
            return 0
        if operation == "-C":
            return 0 if self._normalized(arguments) in self.rules[family] else 1
        if operation == "-D":
            self.rules[family].discard(self._normalized(arguments))
            return 0
        if operation == "-F":
            self.rules[family].clear()
            return 0
        if operation == "-X":
            self.chains[family] = False
            return 0
        raise AssertionError(argv)


class AdoptionRunner:
    def __init__(self) -> None:
        self.active = True
        self.enabled = True
        self.commands: list[tuple[str, ...]] = []

    def status(self, argv):
        command = tuple(argv)
        self.commands.append(command)
        if command[1:3] == ("is-active", "--quiet"):
            return 0 if self.active else 3
        if command[1:3] == ("is-enabled", "--quiet"):
            return 0 if self.enabled else 1
        if command[1:3] == ("stop", "devcoordinator-broker.service"):
            self.active = False
            return 0
        if command[1:4] == ("enable", "--now", "devcoordinator-broker.service"):
            self.enabled = True
            self.active = True
            return 0
        if command[1:3] == ("start", "devcoordinator-broker.service"):
            self.active = True
            return 0
        return 0


def sealed_preparation_state(release: Path, rendered: Path) -> dict[str, object]:
    state, _authority, _testd = fixtures.through_seal(release=release)
    state = cutover.transition(
        state,
        evidence_kind="profile-inventory-readiness",
        evidence=fixtures.profile_inventory_readiness(release=release),
    )
    unsigned = {
        key: value
        for key, value in state.items()
        if key not in {"schema_version", "kind", "document_sha256"}
    }
    unsigned["rendered_units"] = str(rendered)
    return cutover.seal(cutover.STATE_KIND, unsigned)


def host_preflight_document(release: Path, *, observed_at: str | None = None) -> dict[str, object]:
    script = release / "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_preflight.py"
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    return cutover.seal(
        activation.HOST_PREFLIGHT_KIND,
        {
            "ok": True,
            "blocking": True,
            "release_root": str(release.parent),
            "release_digest": release.name,
            "executor": "/usr/bin/python3",
            "executor_sha256": activation._sha256_file(Path("/usr/bin/python3").resolve(strict=True)),
            "script": str(script),
            "script_sha256": activation._sha256_file(script),
            "observed_at": observed_at or activation._now(),
            "host_boot_id": boot_id,
            "systemd_version": 257,
            "checks": [
                {"id": identifier, "ok": True, "detail": "verified by focused fixture"}
                for identifier in (
                    "root-authority",
                    "linux-host",
                    "cgroup-v2",
                    "systemd-manager",
                    "systemd-version",
                    "private-loopback-and-credential",
                    "network-namespace-path",
                    "host-loopback-host-127",
                    "host-loopback-nonloopback-denied",
                    "private-loopback-host-denied",
                )
            ],
        },
    )


class ActivationTests(unittest.TestCase):
    def test_command_runner_wraps_every_subprocess_timeout(self) -> None:
        runner = activation.CommandRunner()
        cases = (
            ("run_json", "activation command timed out after 120 seconds"),
            ("status", "activation status command timed out after 120 seconds"),
            ("text", "activation text command timed out after 120 seconds"),
        )
        for method, message in cases:
            with self.subTest(method=method), mock.patch.object(
                activation.subprocess,
                "run",
                side_effect=subprocess.TimeoutExpired(["/usr/bin/fixture"], 120),
            ):
                with self.assertRaisesRegex(
                    activation.ActivationError,
                    message,
                ) as raised:
                    getattr(runner, method)(["/usr/bin/fixture"])
                self.assertIsInstance(
                    raised.exception.__cause__, subprocess.TimeoutExpired
                )

    def test_first_adoption_accepts_explicitly_discarded_fresh_test_store(self) -> None:
        discarded = fixtures.through_discarded_store()
        completion = activation._first_adoption_test_store_completion(discarded)
        self.assertEqual(completion["mode"], "history-discarded")
        self.assertEqual(
            completion["document_sha256"],
            discarded["evidence"]["test-history-discard"]["document_sha256"],
        )
        invalid = {
            key: value
            for key, value in discarded.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        invalid["evidence"] = dict(discarded["evidence"])
        invalid["evidence"].pop("test-history-discard")
        with self.assertRaisesRegex(
            activation.ActivationError,
            "fresh disposable Test Store",
        ):
            activation._first_adoption_test_store_completion(
                cutover.seal(cutover.STATE_KIND, invalid)
            )

    def setUp(self) -> None:
        self.raw = tempfile.TemporaryDirectory(prefix="availability-activation-")
        self.root = Path(self.raw.name)
        self.uid = os.geteuid()
        self.release_root = private_dir(self.root / "releases")
        self.release = self.release_root / DIGEST
        bin_dir = private_dir(self.release / "bin")
        for name in (
            "devcoordinator-edge-publication",
            "devcoordinator-console-slot-control",
        ):
            executable = bin_dir / name
            executable.write_text("#!/bin/sh\nexit 1\n")
            executable.chmod(0o700)
        preflight_wrapper = bin_dir / "devcoordinator-test-preflight"
        preflight_wrapper.write_text("#!/bin/sh\nexit 1\n")
        preflight_wrapper.chmod(0o555)
        background_wrapper = bin_dir / "devcoordinator-background-handoff"
        background_wrapper.write_text("#!/bin/sh\nexit 1\n")
        background_wrapper.chmod(0o555)
        isolation_wrapper = bin_dir / "devcoordinator-project-isolation-audit"
        isolation_wrapper.write_text("#!/bin/sh\nexit 1\n")
        isolation_wrapper.chmod(0o555)
        preflight_script = (
            self.release
            / "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_preflight.py"
        )
        preflight_script.parent.mkdir(parents=True)
        preflight_script.write_text("# immutable fixture\n", encoding="utf-8")
        preflight_script.chmod(0o444)
        self.credentials = credential_files(private_dir(self.root / "credentials"))
        self.legacy_console_env = private_file(
            self.root / "legacy/console.env",
            b"ALLOWED_EMAILS=owner@example.com\n",
        )
        self.background_project_root = private_dir(self.root / "project")
        self.publication_file = private_dir(self.root / "publication") / "routes.json"
        publication(self.publication_file)
        self.state = candidate_state(self.release)
        self.sockets = dict(self.state["evidence"]["candidate"]["socket_inodes"])

    def tearDown(self) -> None:
        self.raw.cleanup()

    def test_first_adoption_repair_rejects_wal_backed_target_drift(self) -> None:
        database = self.root / "wal-repair-authority.sqlite3"
        repository_id = "eb1dc238-f385-505b-bb7a-cce5107df4e9"
        authority_generation = str(uuid.uuid4())
        plan_id = str(uuid.uuid4())
        deployment_id = str(uuid.uuid4())
        applied_at = "2026-07-30T00:00:00.000Z"
        mutation_reason = cutover._authority_repair_mutation_reason(
            plan_id=plan_id,
            deployment_id=deployment_id,
            state_revision_before=7,
        )
        with closing(sqlite3.connect(database)) as connection:
            connection.executescript(
                """
                CREATE TABLE schema_metadata(
                    singleton INTEGER PRIMARY KEY,
                    schema_version INTEGER NOT NULL,
                    database_generation TEXT NOT NULL,
                    state_revision INTEGER NOT NULL,
                    migration_state TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE repositories(
                    repo_id TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    canonical_root TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE repository_installations(
                    repo_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    startup_fenced INTEGER NOT NULL,
                    generation INTEGER NOT NULL,
                    operation_id TEXT,
                    disabled_at TEXT,
                    reason TEXT,
                    actor TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE broker_repository_enrollments(
                    repo_id TEXT NOT NULL
                );
                CREATE TABLE startup_policies(
                    policy_id TEXT PRIMARY KEY,
                    repo_id TEXT NOT NULL,
                    resource_kind TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    policy_kind TEXT NOT NULL,
                    current_value TEXT NOT NULL,
                    desired_disabled_value TEXT NOT NULL,
                    immutable_fingerprint TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE startup_policy_restore_states(
                    policy_id TEXT PRIMARY KEY,
                    repo_id TEXT,
                    resource_kind TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    policy_kind TEXT NOT NULL,
                    policy_immutable_fingerprint TEXT NOT NULL,
                    target_immutable_fingerprint TEXT NOT NULL,
                    control_binding_id TEXT NOT NULL,
                    observation_fingerprint TEXT NOT NULL,
                    native_identity_fingerprint TEXT NOT NULL,
                    captured_value TEXT NOT NULL,
                    restore_required INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    docker_restart_policy TEXT,
                    supervisor_manager TEXT,
                    supervisor_unit_file_state TEXT,
                    supervisor_loaded INTEGER,
                    supervisor_enabled INTEGER,
                    captured_operation_id TEXT NOT NULL,
                    last_restore_permit_id TEXT,
                    capture_generation INTEGER NOT NULL,
                    captured_at TEXT NOT NULL,
                    restored_at TEXT,
                    updated_at TEXT NOT NULL
                );
                """
            )
            connection.execute(
                "INSERT INTO schema_metadata VALUES (1, 12, ?, 8, 'ready', ?)",
                (authority_generation, applied_at),
            )
            connection.execute(
                "INSERT INTO repositories VALUES (?, 'tmp', '/tmp', 3, "
                "'missing', ?)",
                (repository_id, applied_at),
            )
            connection.execute(
                "INSERT INTO repository_installations VALUES "
                "(?, 'disabled', 1, 4, NULL, ?, ?, ?, ?)",
                (
                    repository_id,
                    applied_at,
                    mutation_reason,
                    cutover.AUTHORITY_REPOSITORY_REPAIR_ACTOR,
                    applied_at,
                ),
            )
            connection.commit()
        database.chmod(0o600)
        plan = {
            "plan_id": plan_id,
            "authority_generation": authority_generation,
            "authority_state_revision": 7,
            "repository": {
                "repository_id": repository_id,
                "display_name": "tmp",
                "canonical_root": "/tmp",
                "generation": 2,
                "installation_generation": 3,
            },
            "startup_policies": [],
        }
        initial = database.stat()
        result = {
            "authority_generation": authority_generation,
            "database_identity_after": {
                "device": int(initial.st_dev),
                "inode": int(initial.st_ino),
                "size": int(initial.st_size),
            },
            "repository_id": repository_id,
            "repository_generation_after": 3,
            "installation_generation_after": 4,
            "state_revision_after": 8,
            "repository_state": "missing",
            "installation_status": "disabled",
            "startup_fenced": True,
            "startup_policies": [],
            "enrollment_count": 0,
            "reason": mutation_reason,
            "actor": cutover.AUTHORITY_REPOSITORY_REPAIR_ACTOR,
            "applied_at": applied_at,
        }
        omitted = activation._verify_first_adoption_tmp_repair_unnecessary(
            database,
            expected_uid=self.uid,
        )
        self.assertEqual(omitted["mode"], "repair-not-required")
        self.assertEqual(
            omitted["repository"]["repository_id"], repository_id
        )
        writer = sqlite3.connect(database)
        try:
            self.assertEqual(writer.execute("PRAGMA journal_mode = WAL").fetchone()[0], "wal")
            writer.execute("PRAGMA wal_autocheckpoint = 0")
            exact = activation._verify_first_adoption_repair_live_state(
                database=database,
                plan=plan,
                result=result,
                expected_uid=self.uid,
            )
            self.assertEqual(exact["metadata"]["state_revision"], 8)

            writer.execute(
                "UPDATE schema_metadata SET state_revision = 9, updated_at = ?",
                ("2026-07-30T00:01:00.000Z",),
            )
            writer.commit()
            descendant = activation._verify_first_adoption_repair_live_state(
                database=database,
                plan=plan,
                result=result,
                expected_uid=self.uid,
            )
            self.assertEqual(descendant["metadata"]["state_revision"], 9)
            omitted_descendant = (
                activation._verify_first_adoption_tmp_repair_unnecessary(
                    database,
                    expected_uid=self.uid,
                )
            )
            self.assertEqual(omitted_descendant["state_revision"], 9)

            writer.execute(
                "INSERT INTO startup_policies VALUES "
                "('tmp-policy', ?, 'service', 'tmp', 'coordinator', "
                "'enabled', 'disabled', ?, 1, ?)",
                (repository_id, "sha256:" + "a" * 64, applied_at),
            )
            writer.commit()
            with self.assertRaisesRegex(
                activation.ActivationError,
                "/tmp authority repair is still required",
            ):
                activation._verify_first_adoption_tmp_repair_unnecessary(
                    database,
                    expected_uid=self.uid,
                )
            writer.execute(
                "DELETE FROM startup_policies WHERE policy_id = 'tmp-policy'"
            )
            writer.commit()

            main_before_drift = database.read_bytes()
            identity_before_drift = database.stat()
            writer.execute(
                "UPDATE repositories SET state = 'active', generation = 4, "
                "updated_at = '2026-07-30T00:02:00.000Z' WHERE repo_id = ?",
                (repository_id,),
            )
            writer.execute(
                "UPDATE repository_installations SET status = 'installed', "
                "startup_fenced = 0, generation = 5, disabled_at = NULL, "
                "reason = NULL, actor = 'agent', "
                "updated_at = '2026-07-30T00:02:00.000Z' WHERE repo_id = ?",
                (repository_id,),
            )
            writer.execute(
                "UPDATE schema_metadata SET state_revision = 10, "
                "updated_at = '2026-07-30T00:02:00.000Z'"
            )
            writer.commit()
            identity_after_drift = database.stat()
            self.assertEqual(
                (
                    identity_after_drift.st_dev,
                    identity_after_drift.st_ino,
                    identity_after_drift.st_size,
                    database.read_bytes(),
                ),
                (
                    identity_before_drift.st_dev,
                    identity_before_drift.st_ino,
                    identity_before_drift.st_size,
                    main_before_drift,
                ),
            )
            with self.assertRaisesRegex(
                activation.ActivationError,
                "semantic state changed",
            ):
                activation._verify_first_adoption_repair_live_state(
                    database=database,
                    plan=plan,
                    result=result,
                    expected_uid=self.uid,
                )
            with self.assertRaisesRegex(
                activation.ActivationError,
                "/tmp authority repair is still required",
            ):
                activation._verify_first_adoption_tmp_repair_unnecessary(
                    database,
                    expected_uid=self.uid,
                )

            writer.execute(
                "DELETE FROM repository_installations WHERE repo_id = ?",
                (repository_id,),
            )
            writer.execute(
                "DELETE FROM repositories WHERE repo_id = ?",
                (repository_id,),
            )
            writer.commit()
            absent = activation._verify_first_adoption_tmp_repair_unnecessary(
                database,
                expected_uid=self.uid,
            )
            self.assertIsNone(absent["repository"])
        finally:
            writer.close()

    def _credential_migration_fixture(
        self, name: str
    ) -> tuple[Path, dict[str, Path], Path, Path]:
        root = private_dir(self.root / name)
        legacy = private_file(
            root / "legacy/console.env",
            (
                "SESSION_SECRET=" + "1" * 64 + "\n"
                "GOOGLE_CLIENT_ID=123456789-test.apps.googleusercontent.com\n"
                "GOOGLE_CLIENT_SECRET=fixture-google-client-secret\n"
            ).encode(),
        )
        destinations = {
            **self.credentials,
            "session-secret": root / "new/session",
            "oidc-client-id": root / "new/client-id",
            "oidc-client-secret": root / "new/client-secret",
        }
        return (
            legacy,
            destinations,
            root / "rollback",
            root / "migration.json",
        )

    def test_credentials_are_migrated_without_secret_disclosure(self) -> None:
        legacy, destinations, rollback, _attestation = (
            self._credential_migration_fixture("credential-success")
        )
        destinations["tls-key"].chmod(0o660)
        document = activation.migrate_credentials(
            legacy_env=legacy,
            legacy_source_uid=self.uid,
            destinations=destinations,
            rollback_directory=rollback,
            expected_uid=self.uid,
        )
        serialized = json.dumps(document)
        self.assertNotIn("fixture-google-client-secret", serialized)
        self.assertEqual(document["legacy_source_uid"], self.uid)
        self.assertEqual(document["publication_authority_uid"], self.uid)
        self.assertEqual(
            set(document["legacy_sources"]),
            {"console-env"},
        )
        self.assertEqual(set(destinations), set(activation.DEFAULT_CREDENTIALS))
        self.assertNotIn("api-token", destinations)
        for name in ("session-secret", "oidc-client-id", "oidc-client-secret"):
            self.assertEqual(stat.S_IMODE(destinations[name].stat().st_mode), 0o600)
        self.assertEqual(
            activation.verify_credential_migration(
                document,
                legacy_env=legacy,
                legacy_source_uid=self.uid,
                destinations=destinations,
                expected_uid=self.uid,
            ),
            document,
        )

    def test_credentials_reuse_current_externalized_layout(self) -> None:
        legacy, destinations, rollback, _attestation = (
            self._credential_migration_fixture("credential-externalized")
        )
        legacy.write_text(
            "DOMAIN=vr.ae\nCONSOLE_SUBDOMAIN=console\n",
            encoding="utf-8",
        )
        expected = {
            "session-secret": b"1" * 64 + b"\n",
            "oidc-client-id": b"123456789-test.apps.googleusercontent.com\n",
            "oidc-client-secret": b"fixture-google-client-secret\n",
        }
        for name, payload in expected.items():
            private_file(destinations[name], payload)

        document = activation.migrate_credentials(
            legacy_env=legacy,
            legacy_source_uid=self.uid,
            destinations=destinations,
            rollback_directory=rollback,
            expected_uid=self.uid,
        )
        self.assertTrue(
            all(
                document["credentials"][name]["changed"] is False
                for name in expected
            )
        )
        self.assertEqual(
            activation.verify_credential_migration(
                document,
                legacy_env=legacy,
                legacy_source_uid=self.uid,
                destinations=destinations,
                expected_uid=self.uid,
            ),
            document,
        )

    def test_credential_migration_rejects_mixed_inline_and_externalized_layout(
        self,
    ) -> None:
        legacy, destinations, rollback, _attestation = (
            self._credential_migration_fixture("credential-mixed-layout")
        )
        legacy.write_text("SESSION_SECRET=" + "1" * 64 + "\n", encoding="utf-8")
        with self.assertRaisesRegex(
            activation.ActivationError,
            "credential fields are incomplete",
        ):
            activation.migrate_credentials(
                legacy_env=legacy,
                legacy_source_uid=self.uid,
                destinations=destinations,
                rollback_directory=rollback,
                expected_uid=self.uid,
            )

    def test_credential_migration_rejects_wrong_legacy_source_owner(self) -> None:
        legacy, destinations, rollback, _attestation = (
            self._credential_migration_fixture("credential-wrong-source-owner")
        )
        with self.assertRaisesRegex(activation.ActivationError, "owned by UID"):
            activation.migrate_credentials(
                legacy_env=legacy,
                legacy_source_uid=self.uid + 1,
                destinations=destinations,
                rollback_directory=rollback,
                expected_uid=self.uid,
            )
        self.assertFalse(destinations["session-secret"].exists())

    def test_credential_migration_rejects_source_replacement_and_symlinks(
        self,
    ) -> None:
        legacy, destinations, rollback, _attestation = (
            self._credential_migration_fixture("credential-source-safety")
        )
        legacy_link = legacy.with_name("console-link.env")
        legacy_link.symlink_to(legacy)
        with self.assertRaisesRegex(activation.ActivationError, "must not be a symlink"):
            activation.migrate_credentials(
                legacy_env=legacy_link,
                legacy_source_uid=self.uid,
                destinations=destinations,
                rollback_directory=rollback,
                expected_uid=self.uid,
            )

        original_bounded = activation._bounded_regular
        replaced = False

        def replace_after_identity(path, **arguments):
            nonlocal replaced
            resolved, identity = original_bounded(path, **arguments)
            if arguments.get("label") == "legacy Console environment" and not replaced:
                replacement = private_file(
                    legacy.with_name("replacement.env"),
                    legacy.read_bytes(),
                )
                os.replace(replacement, legacy)
                replaced = True
            return resolved, identity

        with (
            mock.patch.object(
                activation,
                "_bounded_regular",
                side_effect=replace_after_identity,
            ),
            self.assertRaisesRegex(activation.ActivationError, "changed while it was read"),
        ):
            activation.migrate_credentials(
                legacy_env=legacy,
                legacy_source_uid=self.uid,
                destinations=destinations,
                rollback_directory=rollback,
                expected_uid=self.uid,
            )
        self.assertTrue(replaced)

        destination_target = private_file(
            legacy.parent / "existing-session",
            b"2" * 64 + b"\n",
        )
        destinations["session-secret"].parent.mkdir(parents=True, exist_ok=True)
        destinations["session-secret"].symlink_to(destination_target)
        with self.assertRaisesRegex(activation.ActivationError, "must not be a symlink"):
            activation.migrate_credentials(
                legacy_env=legacy,
                legacy_source_uid=self.uid,
                destinations=destinations,
                rollback_directory=rollback,
                expected_uid=self.uid,
            )

    def test_credential_migration_verifier_rejects_destination_owner_change(
        self,
    ) -> None:
        legacy, destinations, rollback, _attestation = (
            self._credential_migration_fixture("credential-destination-owner")
        )
        document = activation.migrate_credentials(
            legacy_env=legacy,
            legacy_source_uid=self.uid,
            destinations=destinations,
            rollback_directory=rollback,
            expected_uid=self.uid,
        )
        unsigned = {
            key: value
            for key, value in document.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        unsigned["publication_authority_uid"] = self.uid + 1
        foreign_authority = cutover.seal(
            activation.CREDENTIAL_MIGRATION_KIND,
            unsigned,
        )
        with self.assertRaisesRegex(activation.ActivationError, "owned by UID"):
            activation.verify_credential_migration(
                foreign_authority,
                legacy_env=legacy,
                legacy_source_uid=self.uid,
                destinations=destinations,
                expected_uid=self.uid + 1,
            )

    def test_migrate_credentials_cli_requires_source_owner_and_replays(
        self,
    ) -> None:
        legacy, destinations, rollback, attestation = (
            self._credential_migration_fixture("credential-cli")
        )
        arguments = [
            "migrate-credentials",
            "--legacy-env",
            str(legacy),
            "--legacy-source-uid",
            str(self.uid),
            "--rollback-directory",
            str(rollback),
            "--attestation",
            str(attestation),
            "--expected-uid",
            str(self.uid),
        ]
        for name, path in destinations.items():
            arguments.extend([f"--{name}", str(path)])
        first_output = io.StringIO()
        with redirect_stdout(first_output):
            self.assertEqual(activation.main(arguments), 0)
        first_response = json.loads(first_output.getvalue())
        self.assertFalse(first_response["replayed"])
        before = {
            name: (
                path.stat().st_dev,
                path.stat().st_ino,
                path.stat().st_mtime_ns,
                activation._sha256_file(path),
            )
            for name, path in destinations.items()
            if name not in {"tls-cert", "tls-key"}
        }
        second_output = io.StringIO()
        with redirect_stdout(second_output):
            self.assertEqual(activation.main(arguments), 0)
        second_response = json.loads(second_output.getvalue())
        self.assertTrue(second_response["replayed"])
        self.assertEqual(first_response["document_sha256"], second_response["document_sha256"])
        self.assertEqual(
            before,
            {
                name: (
                    path.stat().st_dev,
                    path.stat().st_ino,
                    path.stat().st_mtime_ns,
                    activation._sha256_file(path),
                )
                for name, path in destinations.items()
                if name not in {"tls-cert", "tls-key"}
            },
        )
        serialized = attestation.read_text(encoding="utf-8")
        self.assertNotIn("fixture-google-client-secret", serialized)
        self.assertNotIn("fixture-google-client-secret", first_output.getvalue())

        replacement = private_file(
            legacy.with_name("replayed-replacement.env"),
            legacy.read_bytes(),
        )
        os.replace(replacement, legacy)
        replay_failure = io.StringIO()
        with redirect_stderr(replay_failure):
            self.assertEqual(activation.main(arguments), 1)
        self.assertIn(
            "legacy source identity changed",
            replay_failure.getvalue(),
        )
        self.assertEqual(
            before,
            {
                name: (
                    path.stat().st_dev,
                    path.stat().st_ino,
                    path.stat().st_mtime_ns,
                    activation._sha256_file(path),
                )
                for name, path in destinations.items()
                if name not in {"tls-cert", "tls-key"}
            },
        )

        option_index = arguments.index("--legacy-source-uid")
        missing_owner = [
            *arguments[:option_index],
            *arguments[option_index + 2 :],
        ]
        with (
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as parse_failure,
        ):
            activation._parser().parse_args(missing_owner)
        self.assertEqual(parse_failure.exception.code, 2)

        for removed_option in ("--api-token-source", "--api-token-source-uid"):
            with (
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as parse_failure,
            ):
                activation._parser().parse_args(
                    [*arguments, removed_option, "legacy-token"]
                )
            self.assertEqual(parse_failure.exception.code, 2)

    def test_interrupted_candidate_install_restores_exact_prior_graph(self) -> None:
        rendered = private_dir(self.root / "rendered")
        for name in (
            *activation.TOPOLOGY_FILES,
            "devcoordinator-availability.sysusers.conf",
            "devcoordinator-availability.tmpfiles.conf",
        ):
            private_file(rendered / name, f"candidate:{name}\n".encode(), 0o644)
        slot_source = private_file(
            rendered / f"{DIGEST}.env",
            console_slot_payload(),
            0o644,
        )
        unit_root = private_dir(self.root / "systemd")
        sysusers_root = private_dir(self.root / "sysusers")
        tmpfiles_root = private_dir(self.root / "tmpfiles")
        slot_root = private_dir(self.root / "slots")
        sentinel = private_file(
            unit_root / "devcoordinator-api.service", b"prior-api-unit\n", 0o644
        )
        state = sealed_preparation_state(self.release, rendered)
        runner = PrepareRunner(
            unit_root,
            host_preflight=host_preflight_document(self.release),
            fail_enable_at=3,
        )
        with mock.patch.object(activation, "IMMUTABLE_RELEASE_ROOT", self.release_root):
            with self.assertRaisesRegex(activation.ActivationError, "graph was restored"):
                activation.prepare_candidate(
                    state=state,
                    candidate_slot_source=slot_source,
                    legacy_console_env=self.legacy_console_env,
                    background_project_root=self.background_project_root,
                    background_config_transaction=self.root / "background-failed",
                    project_isolation_audit=self.root / "isolation-failed.json",
                    project_isolation_ledger=self.root / "isolation-failed-ledger.json",
                    credentials=self.credentials,
                    rollback_directory=self.root / "graph-rollback",
                    expected_uid=self.uid,
                    runner=runner,
                    oidc_fetcher=oidc,
                    socket_reader=lambda: dict(self.sockets),
                    unit_root=unit_root,
                    sysusers_root=sysusers_root,
                    tmpfiles_root=tmpfiles_root,
                    slot_root=slot_root,
                    background_config_root=private_dir(self.root / "background-config-failed"),
                    topology_validator=lambda _path, _digest: [],
                )
        self.assertEqual(sentinel.read_bytes(), b"prior-api-unit\n")
        self.assertFalse((unit_root / "devcoordinator-edge.service").exists())
        self.assertFalse((slot_root / f"{DIGEST}.env").exists())

    def test_graph_rollback_restores_active_and_enabled_independently(
        self,
    ) -> None:
        prior = {
            "unit-both.service": {"active": True, "enabled": True},
            "unit-active.service": {"active": True, "enabled": False},
            "unit-enabled.service": {"active": False, "enabled": True},
            "unit-neither.service": {"active": False, "enabled": False},
        }

        class UnitStateRunner:
            def __init__(self) -> None:
                self.states = {
                    unit: [True, True]
                    for unit in prior
                }
                self.commands: list[tuple[str, ...]] = []

            def status(self, argv):
                operation = tuple(argv[1:])
                self.commands.append(operation)
                action = argv[1]
                unit = argv[-1]
                if action == "stop":
                    self.states[unit][0] = False
                elif action == "enable":
                    self.states[unit][1] = True
                    if "--now" in argv:
                        self.states[unit][0] = True
                elif action == "disable":
                    self.states[unit][1] = False
                    if "--now" in argv:
                        self.states[unit][0] = False
                elif action == "start":
                    self.states[unit][0] = True
                elif action == "is-active":
                    return 0 if self.states[unit][0] else 3
                elif action == "is-enabled":
                    return 0 if self.states[unit][1] else 1
                return 0

        runner = UnitStateRunner()
        activation._restore_prepared_graph(
            {"prior_units": prior, "prior_files": {}},
            runner=runner,
            expected_uid=self.uid,
        )
        self.assertEqual(
            {
                unit: tuple(state)
                for unit, state in runner.states.items()
            },
            {
                unit: (value["active"], value["enabled"])
                for unit, value in prior.items()
            },
        )
        self.assertFalse(
            any(
                command[0] in {"enable", "disable"}
                and "--now" in command
                for command in runner.commands
            )
        )

    def test_candidate_preparation_attests_loaded_release_graph(self) -> None:
        rendered = private_dir(self.root / "rendered-success")
        for name in (
            *activation.TOPOLOGY_FILES,
            "devcoordinator-availability.sysusers.conf",
            "devcoordinator-availability.tmpfiles.conf",
        ):
            private_file(rendered / name, f"candidate:{name}\n".encode(), 0o644)
        slot_source = private_file(
            rendered / f"{DIGEST}.env",
            console_slot_payload(),
            0o644,
        )
        unit_root = private_dir(self.root / "systemd-success")
        sysusers_root = private_dir(self.root / "sysusers-success")
        tmpfiles_root = private_dir(self.root / "tmpfiles-success")
        slot_root = private_dir(self.root / "slots-success")
        state = sealed_preparation_state(self.release, rendered)
        runner = PrepareRunner(
            unit_root,
            host_preflight=host_preflight_document(self.release),
        )
        with mock.patch.object(activation, "IMMUTABLE_RELEASE_ROOT", self.release_root):
            candidate, credential = activation.prepare_candidate(
                state=state,
                candidate_slot_source=slot_source,
                legacy_console_env=self.legacy_console_env,
                background_project_root=self.background_project_root,
                background_config_transaction=self.root / "background-success",
                project_isolation_audit=self.root / "isolation-success.json",
                project_isolation_ledger=self.root / "isolation-success-ledger.json",
                credentials=self.credentials,
                rollback_directory=self.root / "graph-retained",
                expected_uid=self.uid,
                runner=runner,
                oidc_fetcher=oidc,
                socket_reader=lambda: dict(self.sockets),
                unit_root=unit_root,
                sysusers_root=sysusers_root,
                tmpfiles_root=tmpfiles_root,
                slot_root=slot_root,
                background_config_root=private_dir(self.root / "background-config-success"),
                topology_validator=lambda _path, _digest: [],
            )
        self.assertTrue(candidate["checks_passed"])
        self.assertEqual(
            candidate["preparation"]["credential_preflight_sha256"],
            credential["document_sha256"],
        )
        self.assertEqual(
            set(candidate["ready_units"]), cutover._candidate_units(DIGEST)
        )
        self.assertTrue(
            any(
                Path(command[0]).name == "devcoordinator-test-preflight"
                and list(command[1:]) == ["--json"]
                for command in runner.commands
            ),
            "candidate preparation did not execute the immutable host gate",
        )

    def test_atomic_install_inherits_validated_parent_group(self) -> None:
        parent = private_dir(self.root / "atomic-install-parent")
        destination = parent / "installed.conf"
        with mock.patch.object(activation.os, "fchown") as fchown:
            activation._atomic_install(
                destination,
                b"installed\n",
                expected_uid=self.uid,
            )
        self.assertEqual(fchown.call_count, 1)
        _descriptor, owner_uid, owner_gid = fchown.call_args.args
        self.assertEqual(owner_uid, self.uid)
        self.assertEqual(owner_gid, parent.stat().st_gid)

    def test_clean_adoption_installs_retired_broker_without_managing_it(self) -> None:
        rendered = private_dir(self.root / "rendered-clean-adoption")
        for name in (
            *activation.TOPOLOGY_FILES,
            *activation.HANDOFF_FILES,
            *activation.API_HANDOFF_FILES,
            "devcoordinator-availability.sysusers.conf",
            "devcoordinator-availability.tmpfiles.conf",
        ):
            private_file(rendered / name, f"candidate:{name}\n".encode(), 0o644)
        retired_broker = (
            b"[Service]\n"
            b"StateDirectory=devcoordinator\n"
            b"ReadWritePaths=/var/lib/devcoordinator -/run/devcoordinator\n"
        )
        private_file(
            rendered / activation.FINAL_HARD_GATE_LEGACY_UNIT,
            retired_broker,
            0o644,
        )
        slot_source = private_file(
            rendered / f"{DIGEST}.env",
            console_slot_payload(),
            0o644,
        )
        unit_root = private_dir(self.root / "systemd-clean-adoption")
        sysusers_root = private_dir(self.root / "sysusers-clean-adoption")
        tmpfiles_root = private_dir(self.root / "tmpfiles-clean-adoption")
        slot_root = private_dir(self.root / "slots-clean-adoption")
        legacy_broker = private_file(
            unit_root / activation.FINAL_HARD_GATE_LEGACY_UNIT,
            (
                b"[Service]\n"
                b"RuntimeDirectory=devcoordinator\n"
                b"RuntimeDirectoryPreserve=restart\n"
            ),
            0o644,
        )
        prior_broker_sha256 = activation._sha256_file(legacy_broker)
        runner = PrepareRunner(
            unit_root,
            host_preflight=host_preflight_document(self.release),
        )
        graph_journal = self.root / "graph-clean-adoption-journal.json"

        with mock.patch.object(activation, "IMMUTABLE_RELEASE_ROOT", self.release_root):
            graph, _credential = activation.prepare_candidate(
                state=sealed_preparation_state(self.release, rendered),
                candidate_slot_source=slot_source,
                legacy_console_env=self.legacy_console_env,
                background_project_root=self.background_project_root,
                background_config_transaction=self.root / "background-clean-adoption",
                project_isolation_audit=self.root / "isolation-clean-adoption.json",
                project_isolation_ledger=(
                    self.root / "isolation-clean-adoption-ledger.json"
                ),
                credentials=self.credentials,
                rollback_directory=self.root / "graph-clean-adoption",
                expected_uid=self.uid,
                runner=runner,
                oidc_fetcher=oidc,
                socket_reader=lambda: self.fail(
                    "clean adoption preparation read live sockets"
                ),
                unit_root=unit_root,
                sysusers_root=sysusers_root,
                tmpfiles_root=tmpfiles_root,
                slot_root=slot_root,
                background_config_root=private_dir(
                    self.root / "background-config-clean-adoption"
                ),
                topology_validator=lambda _path, _digest: [],
                expected_port_reservations=FIRST_ADOPTION_PORTS,
                first_adoption_defer_start=True,
                clean_adoption_defer_start=True,
                first_adoption_legacy_authority_database=(
                    self.root / "fresh-authority-clean-adoption.sqlite3"
                ),
                first_adoption_journal=graph_journal,
            )

        broker_path = str(unit_root / activation.FINAL_HARD_GATE_LEGACY_UNIT)
        operation = activation._load_private_journal(
            graph_journal,
            kind=activation.FIRST_ADOPTION_GRAPH_JOURNAL_KIND,
            expected_uid=self.uid,
        )
        self.assertEqual(legacy_broker.read_bytes(), retired_broker)
        self.assertIn(broker_path, graph["installed_files"])
        self.assertNotIn(
            activation.FINAL_HARD_GATE_LEGACY_UNIT,
            graph["deferred_units"],
        )
        self.assertIs(graph["clean_adoption"], True)
        self.assertEqual(
            operation["prior_files"][broker_path]["sha256"],
            prior_broker_sha256,
        )
        self.assertEqual(
            operation["install_plan"][broker_path]["installed_sha256"],
            activation._sha256_bytes(retired_broker),
        )
        self.assertFalse(
            any(
                command
                and command[0] == "/usr/bin/systemctl"
                and activation.FINAL_HARD_GATE_LEGACY_UNIT in command
                for command in runner.commands
            ),
            "clean adoption managed or started the retired broker",
        )

    def test_first_adoption_preparation_installs_without_starting_listeners(self) -> None:
        rendered = private_dir(self.root / "rendered-first-adoption")
        for name in (
            *activation.TOPOLOGY_FILES,
            *activation.HANDOFF_FILES,
            *activation.API_HANDOFF_FILES,
            "devcoordinator-availability.sysusers.conf",
            "devcoordinator-availability.tmpfiles.conf",
        ):
            private_file(rendered / name, f"candidate:{name}\n".encode(), 0o644)
        slot_source = private_file(
            rendered / f"{DIGEST}.env",
            console_slot_payload(),
            0o644,
        )
        unit_root = private_dir(self.root / "systemd-first-adoption")
        sysusers_root = private_dir(self.root / "sysusers-first-adoption")
        tmpfiles_root = private_dir(self.root / "tmpfiles-first-adoption")
        slot_root = private_dir(self.root / "slots-first-adoption")
        runner = PrepareRunner(
            unit_root,
            host_preflight=host_preflight_document(self.release),
        )
        graph_journal = self.root / "graph-first-adoption-journal.json"
        crashed = False

        def crash_after_first_install(name: str) -> None:
            nonlocal crashed
            if not crashed and name.startswith("graph-install-before-journal:"):
                crashed = True
                raise activation.PowerLossSimulation(name)

        with mock.patch.object(activation, "IMMUTABLE_RELEASE_ROOT", self.release_root):
            with self.assertRaises(activation.PowerLossSimulation):
                activation.prepare_candidate(
                    state=sealed_preparation_state(self.release, rendered),
                    candidate_slot_source=slot_source,
                    legacy_console_env=self.legacy_console_env,
                    background_project_root=self.background_project_root,
                    background_config_transaction=self.root / "background-first-adoption",
                    project_isolation_audit=self.root / "isolation-first-adoption.json",
                    project_isolation_ledger=self.root / "isolation-first-adoption-ledger.json",
                    credentials=self.credentials,
                    rollback_directory=self.root / "graph-first-adoption",
                    expected_uid=self.uid,
                    runner=runner,
                    oidc_fetcher=oidc,
                    socket_reader=lambda: self.fail("deferred preparation read live sockets"),
                    unit_root=unit_root,
                    sysusers_root=sysusers_root,
                    tmpfiles_root=tmpfiles_root,
                    slot_root=slot_root,
                    background_config_root=private_dir(
                        self.root / "background-config-first-adoption"
                    ),
                    topology_validator=lambda _path, _digest: [],
                    expected_port_reservations=FIRST_ADOPTION_PORTS,
                    first_adoption_defer_start=True,
                    first_adoption_legacy_authority_database=(
                        self.root / "legacy-authority-first-adoption.sqlite3"
                    ),
                    first_adoption_journal=graph_journal,
                    failpoint=crash_after_first_install,
                )
            graph, credential = activation.prepare_candidate(
                state=sealed_preparation_state(self.release, rendered),
                candidate_slot_source=slot_source,
                legacy_console_env=self.legacy_console_env,
                background_project_root=self.background_project_root,
                background_config_transaction=self.root / "background-first-adoption",
                project_isolation_audit=self.root / "isolation-first-adoption.json",
                project_isolation_ledger=self.root / "isolation-first-adoption-ledger.json",
                credentials=self.credentials,
                rollback_directory=self.root / "graph-first-adoption",
                expected_uid=self.uid,
                runner=runner,
                oidc_fetcher=oidc,
                socket_reader=lambda: self.fail("deferred preparation read live sockets"),
                unit_root=unit_root,
                sysusers_root=sysusers_root,
                tmpfiles_root=tmpfiles_root,
                slot_root=slot_root,
                background_config_root=private_dir(
                    self.root / "background-config-first-adoption"
                ),
                topology_validator=lambda _path, _digest: [],
                expected_port_reservations=FIRST_ADOPTION_PORTS,
                first_adoption_defer_start=True,
                first_adoption_legacy_authority_database=(
                    self.root / "legacy-authority-first-adoption.sqlite3"
                ),
                first_adoption_journal=graph_journal,
            )
        graph_operation = activation._load_private_journal(
            graph_journal,
            kind=activation.FIRST_ADOPTION_GRAPH_JOURNAL_KIND,
            expected_uid=self.uid,
        )
        self.assertEqual(graph_operation["phase"], "complete")
        self.assertEqual(graph_operation["result"], graph)
        self.assertEqual(graph["kind"], activation.FIRST_ADOPTION_GRAPH_KIND)
        self.assertIs(graph["listeners_started"], False)
        self.assertEqual(
            graph["console_slot_ports"],
            {
                "console_outer": FIRST_ADOPTION_PORTS["console_outer"],
                "console_inner": FIRST_ADOPTION_PORTS["console_inner"],
            },
        )
        self.assertIn(
            str(unit_root / activation.API_HANDOFF_SERVICE_UNIT),
            graph["installed_files"],
        )
        self.assertNotIn(
            str(unit_root / activation.FINAL_HARD_GATE_LEGACY_UNIT),
            graph["installed_files"],
            "ordinary first adoption replaced the live legacy writer early",
        )
        self.assertFalse(
            any("enable" in command for command in runner.commands),
            "deferred preparation started or enabled a unit",
        )
        graph_path = self.root / "prepared-graph-resume.json"
        credential_path = self.root / "prepared-credential-resume.json"
        cutover._publish_evidence(graph_path, graph, uid=self.uid)
        resumed = activation._resume_first_adoption_graph(
            graph_path=graph_path,
            credential_path=credential_path,
            release=self.release,
            expected_uid=self.uid,
        )
        self.assertEqual(resumed, graph)
        self.assertEqual(
            cutover.read_private_json(credential_path, uid=self.uid), credential
        )
        for role in ("console_outer", "console_inner"):
            mismatched_ports = dict(FIRST_ADOPTION_PORTS)
            mismatched_ports[role] += 100
            request = {
                "state": str(self.root / "state.json"),
                "ports": first_adoption_port_request(
                    self.root,
                    reservations=mismatched_ports,
                ),
                "candidate": {
                    "graph_evidence": str(graph_path),
                    "credential_evidence": str(credential_path),
                },
                "console": {},
                "authority": {
                    "database": str(self.root / "final-authority.sqlite3"),
                    "legacy_database": graph["project_isolation"][
                        "authority_database"
                    ],
                },
                "api": {},
                "public": {},
                "fleet": {},
                "background": {},
            }
            with (
                self.subTest(changed_prepared_port=role),
                mock.patch.object(
                    cutover,
                    "load_state",
                    return_value={"release": str(self.release)},
                ),
                self.assertRaisesRegex(
                    activation.ActivationError,
                    "prepared graph is bound to another final authority",
                ),
            ):
                activation._first_adoption_live_step(
                    "graph_prepared",
                    request=request,
                    journal={"steps": {}},
                    expected_uid=self.uid,
                    runner=mock.Mock(),
                )

    def test_console_migration_power_loss_replays_published_input(self) -> None:
        root = private_dir(self.root / "console-migration-crash")
        legacy_env = private_file(
            root / "legacy.env",
            (
                "DOMAIN=vr.ae\n"
                "CONSOLE_SUBDOMAIN=console\n"
                "ALLOWED_EMAILS=owner@example.com\n"
            ).encode(),
        )
        legacy_state = private_dir(root / "legacy-state")
        resolution = private_file(
            root / "resolution.json",
            b'{"schema_version":1,"routes":{}}\n',
        )

        class MigrationRunner:
            def run_json(self, argv):
                values = list(argv)
                if "validate-console" in values:
                    return {"ok": True, "files": {}, "routes": 0, "identities": 0, "telegram_bots": 0}
                if "build-publication" in values:
                    output = Path(values[values.index("--output") + 1])
                    body = {
                        "schema_version": 1,
                        "generation": 1,
                        "published_at": "2026-07-28T00:00:00Z",
                        "domain": "vr.ae",
                        "console_host": "console.vr.ae",
                        "release_digest": DIGEST,
                        "maintenance": {"active": False},
                        "session": {"cookie_name": "session"},
                        "console": {"upstream": {"port": 31443}},
                        "routes": {},
                        "access": {"owners": ["owner@example.com"], "grants": {}},
                    }
                    private_file(
                        output,
                        json.dumps(body, sort_keys=True).encode() + b"\n",
                    )
                    return {
                        "ok": True,
                        "output": str(output),
                        "payload_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
                        "routes": 0,
                        "identities": 1,
                    }
                self.fail(f"unexpected migration command: {values}")

        crashed = False

        def failpoint(stage: str) -> None:
            nonlocal crashed
            if stage == "console-publication-before-journal" and not crashed:
                crashed = True
                raise activation.PowerLossSimulation(stage)

        arguments = {
            "release": self.release,
            "legacy_env": legacy_env,
            "legacy_state": legacy_state,
            "console_state": root / "console-state",
            "edge_identity_state": root / "edge-state",
            "console_config": root / "console.env",
            "route_resolution": resolution,
            "private_publication_input": root / "publication-input.json",
            "console_port": 31443,
            "console_uid": self.uid,
            "console_gid": os.getegid(),
            "edge_uid": self.uid,
            "edge_gid": os.getegid(),
            "legacy_uid": self.uid,
            "rollback_directory": root / "rollback",
            "journal_file": root / "migration-journal.json",
            "expected_uid": self.uid,
            "runner": MigrationRunner(),
        }
        with self.assertRaises(activation.PowerLossSimulation):
            activation.migrate_legacy_console_state(
                **arguments, failpoint=failpoint
            )
        result = activation.migrate_legacy_console_state(**arguments)
        operation = activation._load_private_journal(
            root / "migration-journal.json",
            kind=activation.CONSOLE_STATE_MIGRATION_JOURNAL_KIND,
            expected_uid=self.uid,
        )
        self.assertEqual(operation["phase"], "complete")
        self.assertEqual(operation["result"], result)

    def test_candidate_acceptance_rejects_pending_project_isolation(self) -> None:
        base = {
            "ok": True,
            "kind": activation.PROJECT_ISOLATION_VERIFICATION_KIND,
            "audit_counts": {
                "compliant": 3,
                "legacy_requires_recreation": 0,
                "unobservable": 0,
            },
            "ledger_counts": {"pending": 1, "completed": 4, "retired": 0},
            "project_isolation_complete": False,
        }
        with self.assertRaisesRegex(
            activation.ActivationError, "all managed project runtimes"
        ):
            activation.require_complete_project_runtime_isolation(base)
        complete = {
            **base,
            "ledger_counts": {"pending": 0, "completed": 5, "retired": 0},
            "project_isolation_complete": True,
        }
        self.assertEqual(
            activation.require_complete_project_runtime_isolation(complete), complete
        )

    def test_api_handoff_journal_resumes_and_removes_only_its_rules(self) -> None:
        runner = ApiFirewallRunner()
        journal = private_dir(self.root / "api-handoff") / "journal.json"
        with mock.patch.object(activation.os, "geteuid", return_value=self.uid):
            started = activation.api_handoff_transaction(
                journal_file=journal,
                handoff_port=39876,
                action="start",
                expected_uid=self.uid,
                runner=runner,
                listener_reader=lambda port: port + 100,
                api_probe=lambda _port: 200,
                binaries={
                    "iptables": Path("/sbin/iptables"),
                    "iptables-save": Path("/sbin/iptables-save"),
                },
            )
            resumed = activation.api_handoff_transaction(
                journal_file=journal,
                handoff_port=39876,
                action="start",
                expected_uid=self.uid,
                runner=runner,
                listener_reader=lambda port: port + 100,
                api_probe=lambda _port: 200,
                binaries={
                    "iptables": Path("/sbin/iptables"),
                    "iptables-save": Path("/sbin/iptables-save"),
                },
            )
            finished = activation.api_handoff_transaction(
                journal_file=journal,
                handoff_port=39876,
                action="finish",
                expected_uid=self.uid,
                runner=runner,
                listener_reader=lambda port: port + 100,
                api_probe=lambda _port: 200,
                binaries={
                    "iptables": Path("/sbin/iptables"),
                    "iptables-save": Path("/sbin/iptables-save"),
                },
            )
        self.assertEqual(started["phase"], "legacy_stopped")
        self.assertEqual(resumed["phase"], "legacy_stopped")
        self.assertEqual(finished["phase"], "complete")
        self.assertFalse(runner.legacy_api_active)
        self.assertFalse(runner.legacy_api_enabled)
        self.assertFalse(runner.chain)
        self.assertIn("-A FOREIGN -j ACCEPT", runner.text(["/sbin/iptables-save"]))

    def test_api_health_probe_requires_exact_http_200(self) -> None:
        runner = ApiFirewallRunner()
        with self.assertRaisesRegex(
            activation.ActivationError, "health probe failed"
        ):
            activation.start_api_handoff(
                handoff_port=39875,
                operation_id=str(uuid.uuid4()),
                runner=runner,
                listener_reader=lambda port: port + 100,
                api_probe=lambda _port: 401,
                binaries={
                    "iptables": Path("/sbin/iptables"),
                    "iptables-save": Path("/sbin/iptables-save"),
                },
            )

    def test_api_handoff_cannot_complete_when_temporary_teardown_fails(
        self,
    ) -> None:
        class TeardownFailureRunner(ApiFirewallRunner):
            fail_teardown = False

            def status(self, argv):
                values = list(argv)
                if (
                    self.fail_teardown
                    and values
                    == [
                        "/usr/bin/systemctl",
                        "disable",
                        "--now",
                        activation.API_HANDOFF_SERVICE_UNIT,
                    ]
                ):
                    return 1
                return super().status(values)

        journal = (
            private_dir(self.root / "api-teardown-failure")
            / "journal.json"
        )
        runner = TeardownFailureRunner()
        binaries = {
            "iptables": Path("/sbin/iptables"),
            "iptables-save": Path("/sbin/iptables-save"),
        }
        with mock.patch.object(
            activation.os, "geteuid", return_value=self.uid
        ):
            activation.api_handoff_transaction(
                journal_file=journal,
                handoff_port=39877,
                action="start",
                expected_uid=self.uid,
                runner=runner,
                listener_reader=lambda port: port + 100,
                api_probe=lambda _port: 200,
                binaries=binaries,
            )
            runner.fail_teardown = True
            with self.assertRaisesRegex(
                activation.ActivationError,
                "temporary API handoff unit",
            ):
                activation.api_handoff_transaction(
                    journal_file=journal,
                    handoff_port=39877,
                    action="finish",
                    expected_uid=self.uid,
                    runner=runner,
                    listener_reader=lambda port: port + 100,
                    api_probe=lambda _port: 200,
                    binaries=binaries,
                )
        persisted = activation._load_api_handoff_journal(
            journal, expected_uid=self.uid
        )
        self.assertEqual(persisted["phase"], "final_ready")

    def test_api_handoff_rollback_restores_exact_legacy_service(self) -> None:
        runner = ApiFirewallRunner()
        journal = private_dir(self.root / "api-handoff-rollback") / "journal.json"
        binaries = {
            "iptables": Path("/sbin/iptables"),
            "iptables-save": Path("/sbin/iptables-save"),
        }
        with mock.patch.object(activation.os, "geteuid", return_value=self.uid):
            activation.api_handoff_transaction(
                journal_file=journal,
                handoff_port=39877,
                action="start",
                expected_uid=self.uid,
                runner=runner,
                listener_reader=lambda port: port + 100,
                api_probe=lambda _port: 200,
                binaries=binaries,
            )
            self.assertFalse(runner.legacy_api_active)
            self.assertFalse(runner.legacy_api_enabled)
            rolled_back = activation.api_handoff_transaction(
                journal_file=journal,
                handoff_port=39877,
                action="rollback",
                expected_uid=self.uid,
                runner=runner,
                listener_reader=lambda port: port + 100,
                api_probe=lambda _port: 200,
                binaries=binaries,
            )
        self.assertEqual(rolled_back["phase"], "rolled_back")
        self.assertTrue(runner.legacy_api_active)
        self.assertTrue(runner.legacy_api_enabled)
        self.assertFalse(runner.chain)
        self.assertIn(
            (
                "enable",
                "--now",
                activation.LEGACY_API_SERVICE_UNIT,
            ),
            runner.systemd,
        )

    def test_first_adoption_dependency_order_and_handoff_profile_are_distinct(
        self,
    ) -> None:
        steps = list(activation.FIRST_ADOPTION_STEPS)
        ordered = (
            "legacy_writer_guarded",
            "storage_split",
            "legacy_writer_retired",
            "snapshotd_ready",
            "authority_test_plane_ready",
            "api_bootstrap_profile_ready",
            "api_handoff_ready",
            "api_final_profile_ready",
            "api_ready",
            "maintenance_released",
            "profile_inventory_ready",
            "project_isolation_ready",
            "fleet_ready",
            "candidate_recorded",
            "legacy_writer_committed",
        )
        self.assertEqual(
            sorted((steps.index(name), name) for name in ordered),
            [(steps.index(name), name) for name in ordered],
        )
        unit = (
            ROOT / "deploy/devcoordinator-api-handoff.service"
        ).read_text(encoding="utf-8")
        self.assertIn(str(activation.API_HANDOFF_PROFILE_PATH), unit)
        self.assertNotIn(cutover.PROTECTED_PROFILE_PATH, unit)

    def test_first_adoption_activation_consumes_exact_top_level_browser_binding(
        self,
    ) -> None:
        root = private_dir(self.root / "first-adoption-browser-binding")
        activation_path = root / "activation.json"
        browser = {
            "runtime_lock": str(root / "runtime-lock.json"),
            "storage_state": str(root / "storage-state.json"),
            "signing_key": str(root / "signing-key"),
            "journal": str(root / "browser-journal.json"),
            "attestation": str(root / "browser-attestation.json"),
            "consumption": str(root / "browser-consumption.json"),
        }
        candidate = {
            "migration_seal_sha256": "a" * 64,
            "socket_inodes": {"authority": 101},
            "preparation": {"credential_preflight_sha256": "b" * 64},
        }
        current = {
            "release": str(self.release),
            "cutover_id": "11111111-1111-4111-8111-111111111111",
            "evidence": {
                "candidate": candidate,
                "profile-inventory-readiness": {
                    "document_sha256": "c" * 64,
                },
            },
        }
        request = {
            "state": str(root / "state.json"),
            "ports": first_adoption_port_request(root),
            "candidate": {"activation_evidence": str(activation_path)},
            "browser": browser,
            "console": {"console_port": 31443},
            "authority": {},
            "api": {},
            "public": {"publication": str(root / "routes.json")},
            "fleet": {},
            "background": {},
        }
        handoff = {
            "phase": "complete",
            "document_sha256": "d" * 64,
            "continuity_probe": {"sealed": True},
        }
        continuity = {
            "connection_refused_count": 0,
            "project_route_failures": 0,
        }
        publication = {
            "publication": {"generation": 7},
            "payload_sha256": "e" * 64,
        }
        browser_binding = {
            "browser_lcp_attestation_sha256": "f" * 64,
            "browser_lcp_consumption_sha256": "0" * 64,
        }
        completed = {"document_sha256": "1" * 64}

        with (
            mock.patch.object(cutover, "load_state", return_value=current),
            mock.patch.object(
                cutover, "_continuity_probe", return_value=continuity
            ),
            mock.patch.object(
                activation,
                "verify_nonempty_retained_routes",
                return_value={"document_sha256": "2" * 64},
            ),
            mock.patch.object(
                activation, "_load_publication", return_value=publication
            ),
            mock.patch.object(
                activation, "socket_inodes", return_value={"authority": 101}
            ),
            mock.patch.object(
                activation,
                "bind_browser_lcp_acceptance",
                return_value=browser_binding,
            ) as bind_browser,
            mock.patch.object(
                activation,
                "finalize_browser_bound_activation",
                return_value=completed,
            ) as finalize,
            mock.patch.object(cutover, "record_evidence", return_value=current),
        ):
            result = activation._first_adoption_live_step(
                "activation_recorded",
                request=request,
                journal={"steps": {"public_handoff": handoff}},
                expected_uid=self.uid,
                runner=mock.Mock(),
            )

        self.assertEqual(result, completed)
        binding_arguments = bind_browser.call_args.kwargs
        self.assertEqual(binding_arguments["runtime_lock"], Path(browser["runtime_lock"]))
        self.assertEqual(binding_arguments["storage_state"], Path(browser["storage_state"]))
        self.assertEqual(binding_arguments["signing_key"], Path(browser["signing_key"]))
        self.assertEqual(binding_arguments["journal"], Path(browser["journal"]))
        self.assertEqual(binding_arguments["attestation"], Path(browser["attestation"]))
        self.assertEqual(binding_arguments["consumption"], Path(browser["consumption"]))
        finalize.assert_called_once_with(
            state=current,
            pending_activation=mock.ANY,
            browser_binding=browser_binding,
        )

        invalid = {
            **request,
            "candidate": {
                "activation_evidence": str(root / "invalid-activation.json")
            },
            "browser": {**browser},
        }
        del invalid["browser"]["storage_state"]
        with (
            mock.patch.object(cutover, "load_state", return_value=current),
            mock.patch.object(
                cutover, "_continuity_probe", return_value=continuity
            ),
            mock.patch.object(
                activation,
                "verify_nonempty_retained_routes",
                return_value={"document_sha256": "2" * 64},
            ),
            mock.patch.object(
                activation, "_load_publication", return_value=publication
            ),
            mock.patch.object(
                activation, "socket_inodes", return_value={"authority": 101}
            ),
            mock.patch.object(
                activation, "bind_browser_lcp_acceptance"
            ) as invalid_bind,
        ):
            with self.assertRaisesRegex(
                activation.BrowserAcceptancePending,
                "browser acceptance is incomplete",
            ):
                activation._first_adoption_live_step(
                    "activation_recorded",
                    request=invalid,
                    journal={"steps": {"public_handoff": handoff}},
                    expected_uid=self.uid,
                    runner=mock.Mock(),
                )
        invalid_bind.assert_not_called()

    def test_legacy_writer_handoff_uses_only_immutable_release_wrapper(self) -> None:
        operation_id = str(uuid.uuid4())
        outer_id = str(uuid.uuid4())
        root = self.root / "legacy-writer-wrapper"
        binding = {
            "bridge_transaction": str(root / "bridge"),
            "bridge_operation_id": operation_id,
            "bridge_journal_sha256": "a" * 64,
            "database": str(root / "legacy.sqlite3"),
            "profile": str(root / "profile.json"),
            "socket": "/run/devcoordinator-authority.sock",
            "dropin": (
                "/etc/systemd/system/devcoordinator-broker.service.d/"
                "95-schema12-cutover-bridge.conf"
            ),
            "retirement_guard": (
                "/etc/systemd/system/devcoordinator-broker.service.d/"
                "99-schema13-retired-legacy-broker.conf"
            ),
            "handoff_journal": str(root / "handoff.json"),
        }
        runner = mock.Mock()
        runner.run_json.return_value = {
            "operation_id": operation_id,
            "outer_transaction_id": outer_id,
            "phase": "armed",
            "document_sha256": "b" * 64,
        }
        result = activation._legacy_writer_handoff(
            action="handoff-arm",
            release=self.release,
            legacy_writer=binding,
            outer_transaction_id=outer_id,
            expected_journal_sha256="a" * 64,
            expected_uid=self.uid,
            runner=runner,
        )
        self.assertEqual(result["phase"], "armed")
        argv = runner.run_json.call_args.args[0]
        self.assertEqual(
            argv[0], str(self.release / "bin/devcoordinator-schema12-bridge")
        )
        self.assertNotIn(str(ROOT), argv[0])
        self.assertIn("--expected-journal-sha256", argv)
        self.assertIn("--outer-transaction-id", argv)

    def test_profile_inventory_readiness_replays_after_state_publication(
        self,
    ) -> None:
        root = private_dir(self.root / "inventory-readiness-replay")
        evidence_path = root / "readiness.json"
        readiness = fixtures.profile_inventory_readiness()
        cutover._publish_evidence(evidence_path, readiness, uid=self.uid)
        state = {
            "release": str(self.release),
            "authority_database": fixtures.AUTHORITY_DATABASE,
            "evidence": {"profile-inventory-readiness": readiness},
        }
        request = {
            "state": str(root / "state.json"),
            "ports": first_adoption_port_request(root),
            "candidate": {},
            "console": {},
            "authority": {"database": fixtures.AUTHORITY_DATABASE},
            "api": {"inventory_readiness_evidence": str(evidence_path)},
            "public": {},
            "fleet": {},
            "background": {},
        }
        journal = {
            "steps": {
                "api_final_profile_ready": {
                    "attestation": {"profile_sha256": "c" * 64}
                }
            }
        }
        with (
            mock.patch.object(cutover, "load_state", return_value=state),
            mock.patch.object(
                cutover,
                "verify_profile_inventory_readiness",
                return_value=readiness,
            ) as verify,
            mock.patch.object(cutover, "record_evidence", return_value=state) as record,
            mock.patch.object(
                cutover,
                "_publish_evidence",
                side_effect=AssertionError(
                    "replay must not republish readiness evidence"
                ),
            ),
        ):
            replay = activation._first_adoption_live_step(
                "profile_inventory_ready",
                request=request,
                journal=journal,
                expected_uid=self.uid,
                runner=mock.Mock(),
            )
        self.assertEqual(replay, readiness)
        self.assertEqual(
            verify.call_args.kwargs["verified_at"], readiness["verified_at"]
        )
        record.assert_called_once()

    def test_profile_rollback_resume_binds_current_catalog_generation(
        self,
    ) -> None:
        root = private_dir(self.root / "profile-rollback-resume")
        journal = root / "journal.json"
        activation._write_private_journal(
            journal,
            kind=activation.PROFILE_PUBLICATION_JOURNAL_KIND,
            payload={
                "operation_id": str(uuid.uuid4()),
                "binding": {},
                "phase": "planned",
                "prior_profile": {"existed": False, "backup": None},
                "created_at": activation._now(),
                "updated_at": activation._now(),
            },
            expected_uid=self.uid,
        )
        expected = {"attestation": {"document_sha256": "a" * 64}}
        with mock.patch.object(
            activation,
            "publish_first_adoption_profiles",
            return_value=expected,
        ) as publish:
            result = activation._resume_profile_publication_for_rollback(
                publication=None,
                journal_path=journal,
                adoption={
                    "authority": {
                        "database_generation": "final-generation",
                    }
                },
                authority={
                    "database": str(root / "authority.sqlite3")
                },
                api={
                    "profile_path": str(root / "client-profiles.json"),
                    "api_uid": 2302,
                },
                candidate={
                    "rollback_directory": str(root / "rollback")
                },
                path_key="profile_path",
                expected_uid=self.uid,
            )
        self.assertEqual(result, expected)
        self.assertEqual(publish.call_args.kwargs["validation_uid"], 2302)

    def test_profile_restore_is_replay_safe_after_outer_journal_loss(
        self,
    ) -> None:
        root = private_dir(self.root / "profile-restore-replay")
        destination = private_file(
            root / "profile.json", b'{"version":2}\n', 0o644
        )
        attestation = cutover.seal(
            cutover.PROFILE_REPAIR_KIND,
            {
                "profile_path": str(destination),
                "profile_owner_uid": self.uid,
                "profile_mode": "0644",
                "profile_sha256": hashlib.sha256(
                    destination.read_bytes()
                ).hexdigest(),
                "authority_generation": "final-generation",
                "authority_source_sha256": "a" * 64,
                "validation_uid": 2302,
                "repository_ids": ["repo-alpha"],
                "repository_bindings": [],
                "parser_verified": True,
                "atomic_publication_verified": True,
                "created_at": activation._now(),
            },
        )
        publication = {
            "attestation": attestation,
            "prior_profile": {"existed": False, "backup": None},
        }
        journal = root / "journal.json"
        activation._write_private_journal(
            journal,
            kind=activation.PROFILE_PUBLICATION_JOURNAL_KIND,
            payload={
                "operation_id": str(uuid.uuid4()),
                "binding": {},
                "phase": "complete",
                "prior_profile": publication["prior_profile"],
                "result": publication,
                "created_at": activation._now(),
                "updated_at": activation._now(),
            },
            expected_uid=self.uid,
        )
        first = activation._restore_first_adoption_profile(
            publication,
            journal_file=journal,
            expected_uid=self.uid,
        )
        replay = activation._restore_first_adoption_profile(
            publication,
            journal_file=journal,
            expected_uid=self.uid,
        )
        self.assertFalse(destination.exists())
        self.assertIs(first["replayed"], False)
        self.assertIs(replay["replayed"], True)

    def test_maintenance_release_unblocks_real_client_api_then_rearms(
        self,
    ) -> None:
        root = private_dir(self.root / "maintenance-api-integration")
        maintenance_root = private_dir(root / "maintenance")
        operation_id = str(uuid.uuid4())
        started_at = activation._now()
        adoption = cutover.seal(
            activation.AUTHORITY_ADOPTION_KIND,
            {
                "operation_id": operation_id,
                "release_digest": self.release.name,
                "source": {},
                "authority": {},
                "inventory": {},
                "storage_split": {},
                "pointer_path": str(root / "pointer.json"),
                "legacy_source_original_path": str(
                    root / "legacy.sqlite3"
                ),
                "source_rotated": True,
                "retained_source_is_rollback": True,
                "legacy_unit": {"active": True, "enabled": True},
                "maintenance": {
                    "deployment_id": operation_id,
                    "root": str(maintenance_root),
                },
                "created_at": started_at,
            },
        )
        activate_maintenance(
            expected_uid=self.uid,
            expected_gid=os.getegid(),
            deployment_id=operation_id,
            scope=CONTROL_PLANE_MAINTENANCE_SCOPE,
            message=PUBLIC_MAINTENANCE_MESSAGE,
            retry_after_seconds=5,
            started_at=started_at,
            maintenance_root=maintenance_root,
        )

        class CatalogClient(BrokerClient):
            def call(self, request):
                self._require_available(
                    operation_id=request.operation_id
                )
                return {"repositories": []}

        client = CatalogClient(
            root / "unused.sock",
            expected_broker_uid=self.uid,
            expected_socket_gid=os.getegid(),
            maintenance_root=maintenance_root,
        )

        def catalog():
            return client.call(
                BrokerRequest.create(
                    account_id="local",
                    project_id="host",
                    resource_id="catalog",
                    operation=BrokerOperation.TEST_REPOSITORY_CATALOG,
                    arguments={},
                )
            )

        server = dev_coordinator.BoundedThreadingHTTPServer(
            ("127.0.0.1", 0),
            dev_coordinator.ApiHandler,
        )
        thread = threading.Thread(
            target=server.serve_forever, daemon=True
        )
        thread.start()

        def request() -> tuple[int, Mapping[str, object]]:
            connection = http.client.HTTPConnection(
                "127.0.0.1", int(server.server_address[1]), timeout=5
            )
            try:
                connection.request(
                    "GET",
                    "/v1/test-repositories",
                )
                response = connection.getresponse()
                body = json.loads(response.read().decode("utf-8"))
                return response.status, body
            finally:
                connection.close()

        try:
            with (
                mock.patch.object(
                    activation,
                    "CANONICAL_MAINTENANCE_ROOT",
                    maintenance_root,
                ),
                mock.patch.object(
                    dev_coordinator,
                    "coordinated_test_repository_list",
                    side_effect=catalog,
                ),
            ):
                status, body = request()
                self.assertEqual(status, 503)
                self.assertEqual(
                    body["code"], "maintenance_in_progress"
                )
                released = (
                    activation.release_authority_maintenance_for_first_adoption(
                        adoption,
                        release=self.release,
                        maintenance_gid=os.getegid(),
                        operation_journal=root / "authority-journal.json",
                        expected_uid=self.uid,
                    )
                )
                self.assertIs(released["released"], True)
                status, body = request()
                self.assertEqual(status, 200)
                self.assertEqual(body["repositories"], [])
                rearmed = (
                    activation.rearm_authority_maintenance_for_rollback(
                        adoption,
                        release=self.release,
                        maintenance_gid=os.getegid(),
                        operation_journal=root / "authority-journal.json",
                        expected_uid=self.uid,
                    )
                )
                self.assertIs(rearmed["rearmed"], True)
                status, body = request()
                self.assertEqual(status, 503)
                self.assertEqual(
                    body["code"], "maintenance_in_progress"
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_storage_split_reverifies_port_rows_on_legacy_and_final_paths(
        self,
    ) -> None:
        legacy = self.root / "legacy-authority.sqlite3"
        final = self.root / "authority.sqlite3"
        port_bundle = first_adoption_port_bundle(
            self.root,
            authority_database=str(legacy),
        )
        private_file(
            Path(str(first_adoption_port_request(self.root)["bundle"])),
            json.dumps(port_bundle).encode(),
        )
        request = {
            "state": str(self.root / "state.json"),
            "ports": first_adoption_port_request(
                self.root,
                digest=str(port_bundle["document_sha256"]),
            ),
            "candidate": {},
            "console": {},
            "authority": {
                "legacy_database": str(legacy),
                "database": str(final),
                "inventory_database": str(self.root / "inventory.sqlite3"),
                "inventory_publication": str(
                    self.root / "inventory.publication"
                ),
                "split_attestation": str(self.root / "split.json"),
                "adoption_pointer": str(self.root / "adoption.json"),
                "maintenance_root": str(self.root / "maintenance"),
                "maintenance_gid": 2300,
                "authority_uid": self.uid,
                "authority_gid": os.getegid(),
                "inventory_uid": 2304,
                "inventory_gid": 2304,
                "operation_journal": str(
                    self.root / "authority-operation.json"
                ),
            },
            "api": {},
            "public": {},
            "fleet": {},
            "background": {},
        }
        with (
            mock.patch.object(
                cutover,
                "load_state",
                return_value={
                    "release": str(self.release),
                    "release_digest": DIGEST,
                    "legacy_authority_database": str(legacy),
                    "phase": "sealed",
                    "evidence": {},
                    "state_generation": 1,
                },
            ),
            mock.patch.object(
                cutover,
                "verify_first_adoption_port_reservations",
                return_value=port_bundle,
                create=True,
            ),
            mock.patch.object(
                cutover,
                "verify_first_adoption_port_reservation_rows",
                return_value={
                    "authority_database": str(legacy),
                    "roles": sorted(FIRST_ADOPTION_PORTS),
                },
                create=True,
            ) as verify_legacy_rows,
            mock.patch.object(
                cutover,
                "verify_first_adoption_port_reservation_rows_after_adoption",
                side_effect=lambda database, _bundle, _adoption, **_kwargs: {
                    "authority_database": str(database),
                    "roles": sorted(FIRST_ADOPTION_PORTS),
                },
                create=True,
            ) as verify_final_rows,
            mock.patch.object(
                activation,
                "adopt_authority_database",
                return_value={"ok": True},
            ) as adoption,
        ):
            result = activation._first_adoption_live_step(
                "storage_split",
                request=request,
                journal={"steps": {}},
                expected_uid=self.uid,
                runner=mock.Mock(),
            )
        self.assertEqual(result, {"ok": True})
        arguments = adoption.call_args.kwargs
        self.assertEqual(arguments["source_database"], legacy)
        self.assertEqual(arguments["authority_database"], final)
        self.assertIsNone(arguments["retained_source_database"])
        verify_legacy_rows.assert_called_once()
        self.assertEqual(verify_legacy_rows.call_args.args[0], legacy)
        verify_final_rows.assert_called_once()
        self.assertEqual(verify_final_rows.call_args.args[0], final)
        self.assertEqual(verify_final_rows.call_args.args[2], {"ok": True})
        self.assertTrue(
            all(
                call.kwargs["minimum_handoff_remaining_seconds"]
                == activation.FIRST_ADOPTION_MINIMUM_HANDOFF_REMAINING_SECONDS
                for call in (
                    *verify_legacy_rows.call_args_list,
                    *verify_final_rows.call_args_list,
                )
            )
        )

    def test_first_availability_catalogs_setup_without_fleet_mutation(
        self,
    ) -> None:
        root = private_dir(self.root / "post-authority-fleet")
        repository_id = "repo-alpha"
        ready_repository_id = "repo-ready"
        missing_repository_id = "repo-beta"
        invalid_repository_id = "repo-invalid"
        export = cutover.seal(
            cutover.AUTHORITY_REPOSITORY_EXPORT_KIND,
            {
                "authority_generation": "final-generation",
                "repositories": [
                    {
                        "repository_id": repository_id,
                        "owner_uid": 1200,
                        "repository_generation": 7,
                    },
                    {
                        "repository_id": ready_repository_id,
                        "owner_uid": 1202,
                        "repository_generation": 5,
                    },
                    {
                        "repository_id": missing_repository_id,
                        "owner_uid": 1201,
                        "repository_generation": 3,
                    },
                    {
                        "repository_id": invalid_repository_id,
                        "owner_uid": 1203,
                        "repository_generation": 4,
                    },
                ],
                "exported_at": "2026-07-28T20:00:00.000Z",
            },
        )
        replay_export = cutover.seal(
            cutover.AUTHORITY_REPOSITORY_EXPORT_KIND,
            {
                "authority_generation": "final-generation",
                "repositories": export["repositories"],
                "exported_at": "2026-07-28T20:00:01.000Z",
            },
        )
        manifest_template = cutover.seal(
            activation.FIRST_ADOPTION_MANIFEST_TEMPLATE_KIND,
            {
                "operation_id": str(uuid.uuid4()),
                "manifests": [
                    {
                        "repository_id": missing_repository_id,
                        "manifest": {"schema_version": 1, "targets": []},
                    },
                ],
                "created_at": activation._now(),
            },
        )
        manifest_template_path = root / "manifest-template.json"
        cutover._publish_evidence(
            manifest_template_path,
            manifest_template,
            uid=self.uid,
        )

        class FleetRunner:
            def __init__(self) -> None:
                self.actions: list[str] = []

            def run_json(self, argv):
                values = list(argv)
                if "catalog" in values:
                    self.actions.append("catalog")
                    return {
                        "ok": True,
                        "counts": {
                            "ready": 2,
                            "missing": 1,
                            "invalid": 1,
                        },
                        "repositories": [
                            {
                                "repository_id": repository_id,
                                "repository_generation": 7,
                                "owner_uid": 1200,
                                "status": "ready",
                                "adoption_ready": True,
                                "safety_status": "clean",
                                "safety_action_count": 0,
                                "safety_blocker_codes": [],
                                "deletion_scan_complete": True,
                                "deleted_tracked_count": 0,
                            },
                            {
                                "repository_id": ready_repository_id,
                                "repository_generation": 5,
                                "owner_uid": 1202,
                                "status": "ready",
                                "adoption_ready": True,
                                "safety_status": "clean",
                                "safety_action_count": 0,
                                "safety_blocker_codes": [],
                                "deletion_scan_complete": True,
                                "deleted_tracked_count": 0,
                            },
                            {
                                "repository_id": missing_repository_id,
                                "repository_generation": 3,
                                "owner_uid": 1201,
                                "status": "missing",
                                "adoption_ready": False,
                                "safety_status": "clean",
                                "safety_action_count": 0,
                                "safety_blocker_codes": [],
                                "deletion_scan_complete": True,
                                "deleted_tracked_count": 0,
                            },
                            {
                                "repository_id": invalid_repository_id,
                                "repository_generation": 4,
                                "owner_uid": 1203,
                                "status": "invalid",
                                "adoption_ready": False,
                                "safety_status": "blocked",
                                "safety_action_count": 0,
                                "safety_blocker_codes": ["owner-mismatch"],
                                "deletion_scan_complete": True,
                                "deleted_tracked_count": 0,
                            },
                        ],
                    }
                raise AssertionError("first availability attempted a mutation")

        runner = FleetRunner()
        evidence_root = private_dir(root / "evidence")
        request = {
            "state": str(root / "state.json"),
            "ports": first_adoption_port_request(root),
            "candidate": {},
            "console": {},
            "authority": {"database": str(root / "authority.sqlite3")},
            "api": {},
            "public": {},
            "fleet": {
                "authority_export": str(root / "authority-export.json"),
                "evidence_root": str(evidence_root),
                "manifest_template": str(manifest_template_path),
                "manifest_template_sha256": manifest_template[
                    "document_sha256"
                ],
                "manifest_set": str(root / "manifest-set.json"),
                "adoption_request": str(root / "adoption-request.json"),
                "helper": str(root / "uid-helper"),
            },
            "background": {},
        }
        with (
            mock.patch.object(
                cutover,
                "load_state",
                return_value={
                    "release": str(self.release),
                    "phase": "sealed",
                    "evidence": {},
                    "state_generation": 1,
                },
            ),
            mock.patch.object(
                cutover,
                "export_authority_test_repositories",
                side_effect=(export, replay_export),
            ),
        ):
            result = activation._first_adoption_live_step(
                "fleet_ready",
                request=request,
                journal={"steps": {"storage_split": {"ok": True}}},
                expected_uid=self.uid,
                runner=runner,
            )
            replay = activation._first_adoption_live_step(
                "fleet_ready",
                request=request,
                journal={"steps": {"storage_split": {"ok": True}}},
                expected_uid=self.uid,
                runner=runner,
            )
        self.assertEqual(runner.actions, ["catalog"])
        self.assertEqual(result["manifest_mutations"], 0)
        self.assertEqual(
            result["runnable_repository_ids"],
            [repository_id, ready_repository_id],
        )
        self.assertEqual(
            result["setup_repository_ids"],
            [missing_repository_id, invalid_repository_id],
        )
        self.assertEqual(
            result["blocked_repository_ids"], [invalid_repository_id]
        )
        self.assertFalse((root / "manifest-set.json").exists())
        self.assertFalse((root / "adoption-request.json").exists())
        self.assertEqual(replay, result)
        rolled_back = (
            activation._rollback_first_adoption_fleet_transaction(
                release=self.release,
                authority=request["authority"],
                fleet_request=request["fleet"],
                fleet_evidence=result,
                expected_uid=self.uid,
                runner=runner,
            )
        )
        self.assertIs(rolled_back["skipped"], True)
        self.assertEqual(
            rolled_back["mode"],
            activation.FIRST_ADOPTION_FLEET_SETUP_CATALOG_MODE,
        )
        self.assertEqual(runner.actions, ["catalog"])

    def test_fleet_request_output_replays_only_for_exact_content(
        self,
    ) -> None:
        root = private_dir(self.root / "fleet-request-replay")
        output = root / "request.json"
        request = {
            "schema_version": 1,
            "operation_id": str(uuid.uuid4()),
            "excluded_repositories": [],
            "repositories": [],
        }
        first = adoption_cli._write_private_once(
            output, request, expected_uid=self.uid
        )
        replay = adoption_cli._write_private_once(
            output, request, expected_uid=self.uid
        )
        self.assertEqual(first, replay)
        with self.assertRaisesRegex(
            adoption_cli.TestStoreContractError,
            "belongs to another request",
        ):
            adoption_cli._write_private_once(
                output,
                {**request, "repositories": [{"repository_id": "other"}]},
                expected_uid=self.uid,
            )
        output.unlink()
        output.write_text(
            json.dumps(request, indent=2), encoding="utf-8"
        )
        output.chmod(0o600)
        with self.assertRaisesRegex(
            adoption_cli.TestStoreContractError,
            "belongs to another request",
        ):
            adoption_cli._write_private_once(
                output, request, expected_uid=self.uid
            )


    def test_manifest_template_builder_is_sealed_and_replay_safe(
        self,
    ) -> None:
        root = private_dir(self.root / "manifest-template-builder")
        source = root / "input.json"
        output = root / "template.json"
        cutover._publish_evidence(
            source,
            {
                "schema_version": 1,
                "operation_id": str(uuid.uuid4()),
                "manifests": [],
            },
            uid=self.uid,
        )
        arguments = argparse.Namespace(
            input=str(source),
            output=str(output),
            expected_uid=self.uid,
        )
        with mock.patch.object(
            activation.os, "geteuid", return_value=self.uid
        ):
            first = activation.build_first_adoption_manifest_template(
                arguments
            )
            replay = activation.build_first_adoption_manifest_template(
                arguments
            )
        self.assertEqual(first, replay)
        self.assertEqual(
            first["kind"],
            activation.FIRST_ADOPTION_MANIFEST_TEMPLATE_KIND,
        )
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_retained_inventory_gate_rejects_empty_repository_projection(self) -> None:
        with self.assertRaisesRegex(
            activation.ActivationError, "no attributable repositories"
        ):
            activation._retained_inventory_counts(
                {
                    "inventory": {
                        "repositories": [],
                        "servers": [],
                        "docker": {"containers": []},
                    }
                }
            )

    def test_first_adoption_transaction_resumes_one_journal(self) -> None:
        root = private_dir(self.root / "transaction")
        port_bundle_path = root / "port-reservations.json"
        port_bundle = first_adoption_port_bundle(
            root,
            authority_database=str(root / "legacy-authority.sqlite3"),
        )
        private_file(
            port_bundle_path,
            json.dumps(port_bundle).encode(),
        )
        request = cutover.seal(
            activation.FIRST_ADOPTION_REQUEST_KIND,
            {
                "state": str(root / "state.json"),
                "repair_plan": str(root / "repair-plan.json"),
                "repair_result": str(root / "repair-result.json"),
                "ports": first_adoption_port_request(
                    root,
                    digest=str(port_bundle["document_sha256"]),
                ),
                "legacy_writer": {
                    "bridge_transaction": str(root / "bridge-transaction"),
                    "bridge_operation_id": str(uuid.uuid4()),
                    "bridge_journal_sha256": "b" * 64,
                    "database": str(root / "legacy-authority.sqlite3"),
                    "profile": cutover.PROTECTED_PROFILE_PATH,
                    "socket": "/run/devcoordinator-authority.sock",
                    "dropin": (
                        "/etc/systemd/system/"
                        "devcoordinator-broker.service.d/"
                        "95-schema12-cutover-bridge.conf"
                    ),
                    "retirement_guard": (
                        "/etc/systemd/system/"
                        "devcoordinator-broker.service.d/"
                        "99-schema13-retired-legacy-broker.conf"
                    ),
                    "handoff_journal": str(
                        root
                        / "bridge-transaction"
                        / "writer-handoff-journal.json"
                    ),
                },
                "candidate": {
                    "slot_source": str(root / "slot.env"),
                    "rollback_directory": str(root / "graph-rollback"),
                    "legacy_console_env": str(root / "legacy.env"),
                    "background_project_root": str(root / "project"),
                    "background_config_transaction": str(root / "background"),
                    "project_isolation_audit": str(root / "isolation.json"),
                    "project_isolation_ledger": str(root / "isolation-ledger.json"),
                    "graph_evidence": str(root / "graph.json"),
                    "graph_journal": str(root / "graph-journal.json"),
                    "credential_evidence": str(root / "credential.json"),
                    "candidate_evidence": str(root / "candidate.json"),
                    "activation_evidence": str(root / "activation.json"),
                },
                "browser": {
                    "runtime_lock": str(root / "browser-runtime-lock.json"),
                    "storage_state": str(root / "browser-storage-state.json"),
                    "signing_key": str(root / "browser-signing-key"),
                    "journal": str(root / "browser-journal.json"),
                    "attestation": str(
                        root
                        / "browser-lcp-11111111-1111-4111-8111-111111111111.attestation.json"
                    ),
                    "consumption": str(
                        root
                        / "browser-lcp-11111111-1111-4111-8111-111111111111.consumption.json"
                    ),
                },
                "console": {
                    "legacy_state": str(root / "legacy-state"),
                    "console_state": str(root / "console-state"),
                    "edge_identity_state": str(root / "edge-state"),
                    "console_config": str(root / "console.env"),
                    "route_resolution": str(root / "route-resolution.json"),
                    "publication_input": str(root / "publication-input.json"),
                    "console_port": 31443,
                    "console_uid": 2303,
                    "console_gid": 2303,
                    "edge_uid": 2301,
                    "edge_gid": 2301,
                    "legacy_uid": self.uid,
                    "rollback_directory": str(root / "console-rollback"),
                    "migration_journal": str(root / "console-migration.json"),
                },
                "authority": {
                    "legacy_database": str(root / "legacy-authority.sqlite3"),
                    "database": cutover.FINAL_AUTHORITY_DATABASE_PATH,
                    "inventory_database": str(root / "inventory.sqlite3"),
                    "inventory_publication": str(root / "inventory.publication"),
                    "split_attestation": str(root / "split.json"),
                    "adoption_pointer": str(root / "adoption.json"),
                    "operation_journal": str(root / "authority-operation.json"),
                    "maintenance_root": str(
                        activation.CANONICAL_MAINTENANCE_ROOT
                    ),
                    "maintenance_gid": os.getegid(),
                    "authority_uid": 0,
                    "authority_gid": 0,
                    "inventory_uid": 2304,
                    "inventory_gid": 2304,
                },
                "api": {
                    "handoff_port": 39876,
                    "journal": str(root / "api.json"),
                    "profile_path": cutover.PROTECTED_PROFILE_PATH,
                    "bootstrap_profile_path": str(
                        activation.API_HANDOFF_PROFILE_PATH
                    ),
                    "bootstrap_profile_journal": str(
                        root / "bootstrap-profile-journal.json"
                    ),
                    "final_profile_journal": str(
                        root / "final-profile-journal.json"
                    ),
                    "api_uid": 2302,
                    "inventory_readiness_evidence": str(
                        root / "profile-inventory-readiness.json"
                    ),
                },
                "public": {
                    "publication": str(root / "routes.json"),
                    "handoff_journal": str(root / "public.json"),
                    "http_handoff_port": 38080,
                    "https_handoff_port": 38443,
                },
                "fleet": {
                    "authority_export": str(root / "authority-export.json"),
                    "evidence_root": str(root / "fleet"),
                    "manifest_template": str(
                        root / "fleet-manifest-template.json"
                    ),
                    "manifest_template_sha256": "d" * 64,
                    "manifest_set": str(root / "fleet-manifest-set.json"),
                    "adoption_request": str(root / "fleet-request.json"),
                    "helper": str(root / "uid-helper"),
                },
                "background": {
                    "telegram_present": False,
                    "telegram_source": str(root / "telegram-source.json"),
                    "telegram_destination": str(root / "telegram-destination.json"),
                    "telegram_rollback": str(root / "telegram-rollback.json"),
                    "telegram_fence": str(root / "telegram-fence.json"),
                    "source_owner_uid": self.uid,
                    "destination_owner_uid": 2305,
                    "destination_owner_gid": 2305,
                },
            },
        )
        optional_repair_payload = {
            key: value
            for key, value in request.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        optional_repair_payload["repair_plan"] = None
        optional_repair_payload["repair_result"] = None
        optional_repair = activation._first_adoption_request(
            cutover.seal(
                activation.FIRST_ADOPTION_REQUEST_KIND,
                optional_repair_payload,
            )
        )
        self.assertIsNone(optional_repair["repair_plan"])
        self.assertIsNone(optional_repair["repair_result"])
        for missing, retained in (
            ("repair_plan", "repair_result"),
            ("repair_result", "repair_plan"),
        ):
            one_sided = dict(optional_repair_payload)
            one_sided[retained] = request[retained]
            with (
                self.subTest(missing=missing),
                self.assertRaisesRegex(
                    activation.ActivationError,
                    "must both be paths or both be null",
                ),
            ):
                activation._first_adoption_request(
                    cutover.seal(
                        activation.FIRST_ADOPTION_REQUEST_KIND,
                        one_sided,
                    )
                )
        builder_values: dict[str, object] = {
            "state": request["state"],
            "repair_plan": request["repair_plan"],
            "repair_result": request["repair_result"],
            "output": str(root / "request.json"),
            "expected_uid": self.uid,
        }
        for group_name, fields in activation._FIRST_ADOPTION_ARGUMENTS.items():
            group = request[group_name]
            self.assertIsInstance(group, Mapping)
            for field_name, argument_name in fields.items():
                builder_values[argument_name] = group[field_name]
        builder_arguments = argparse.Namespace(**builder_values)
        builder_state = {
            "release_digest": DIGEST,
            "legacy_authority_database": str(
                root / "legacy-authority.sqlite3"
            ),
        }
        with (
            mock.patch.object(
                activation.os, "geteuid", return_value=self.uid
            ),
            mock.patch.object(
                cutover, "load_state", return_value=builder_state
            ),
            mock.patch.object(
                cutover,
                "verify_first_adoption_port_reservations",
                return_value=port_bundle,
                create=True,
            ),
        ):
            built = activation.build_first_adoption_request(builder_arguments)
            rebuilt = activation.build_first_adoption_request(builder_arguments)
        self.assertEqual(built, request)
        self.assertEqual(rebuilt, request)
        self.assertEqual(
            built["ports"]["reservations"], FIRST_ADOPTION_PORTS
        )
        self.assertEqual((root / "request.json").stat().st_mode & 0o777, 0o600)

        for label, changed_bundle in (
            (
                "digest",
                {**port_bundle, "document_sha256": "f" * 64},
            ),
            (
                "release",
                {**port_bundle, "release_digest": OLD_DIGEST},
            ),
            (
                "database",
                {
                    **port_bundle,
                    "authority_database": str(
                        root / "other-authority.sqlite3"
                    ),
                },
            ),
        ):
            with (
                self.subTest(bundle_drift=label),
                mock.patch.object(
                    activation.os, "geteuid", return_value=self.uid
                ),
                mock.patch.object(
                    cutover, "load_state", return_value=builder_state
                ),
                mock.patch.object(
                    cutover,
                    "verify_first_adoption_port_reservations",
                    return_value=changed_bundle,
                    create=True,
                ),
                self.assertRaisesRegex(
                    activation.ActivationError,
                    "port reservations are bound to another cutover",
                ),
            ):
                activation.build_first_adoption_request(builder_arguments)

        request_payload = {
            key: value
            for key, value in request.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        mismatches = (
            ("console", "console_port", "console_outer"),
            ("api", "handoff_port", "handoff_api"),
            ("public", "http_handoff_port", "handoff_http"),
            ("public", "https_handoff_port", "handoff_https"),
        )
        for group_name, field_name, role in mismatches:
            changed = {
                key: (
                    dict(value) if isinstance(value, Mapping) else value
                )
                for key, value in request_payload.items()
            }
            changed[group_name][field_name] = (
                FIRST_ADOPTION_PORTS[role] + 1
            )
            with (
                self.subTest(
                    listener_group=group_name,
                    listener_field=field_name,
                ),
                self.assertRaisesRegex(
                    activation.ActivationError,
                    "listener ports are invalid",
                ),
            ):
                activation._first_adoption_request(
                    cutover.seal(
                        activation.FIRST_ADOPTION_REQUEST_KIND,
                        changed,
                    )
                )
        sealed_state, _authority, _testd = fixtures.through_seal()
        producer = next(
            item
            for item in cutover.next_actions(sealed_state)["actions"]
            if item.get("argv_prefix", [None])[0]
            == "build-first-adoption-request"
        )
        advertised = {
            value
            for value in producer["argv_prefix"]
            if isinstance(value, str) and value.startswith("--")
        }
        for group in producer["required_argument_groups"].values():
            advertised.update(re.findall(r"--[a-z0-9-]+", group))
        parser = activation._parser()
        subparsers = next(
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        builder_parser = subparsers.choices["build-first-adoption-request"]
        required_options = {
            option
            for action in builder_parser._actions
            if action.required
            for option in action.option_strings
        }
        self.assertEqual(advertised, required_options)
        journal_path = root / "journal.json"
        retained_port_rows = {
            "authority_database": str(root / "legacy-authority.sqlite3"),
            "roles": sorted(FIRST_ADOPTION_PORTS),
        }
        initial_steps = {
            step: {"resumed": True}
            for step in activation.FIRST_ADOPTION_STEPS[:3]
        }
        initial_steps["validated"] = {
            "port_reservations_sha256": port_bundle["document_sha256"],
            "port_reservation_rows": retained_port_rows,
        }
        initial = activation._write_first_adoption_transaction(
            journal_path,
            {
                "transaction_id": str(uuid.uuid4()),
                "request_sha256": request["document_sha256"],
                "phase": "console_state_migrated",
                "steps": initial_steps,
                "created_at": activation._now(),
                "updated_at": activation._now(),
            },
            expected_uid=self.uid,
        )
        calls: list[str] = []

        def handler(step, **_kwargs):
            calls.append(step)
            if step == "complete":
                return {
                    "step": step,
                    "port_reservations_sha256": port_bundle[
                        "document_sha256"
                    ],
                    "port_reservation_rows": {
                        **retained_port_rows,
                        "authority_database": cutover.FINAL_AUTHORITY_DATABASE_PATH,
                    },
                }
            return {"step": step}

        with mock.patch.object(activation.os, "geteuid", return_value=self.uid):
            result = activation.execute_first_adoption_transaction(
                request=request,
                journal_file=journal_path,
                attestation=root / "attestation.json",
                rollback_evidence=root / "rollback.json",
                expected_uid=self.uid,
                runner=mock.Mock(),
                step_handler=handler,
            )
        self.assertEqual(result["phase"], "complete")
        self.assertEqual(calls, list(activation.FIRST_ADOPTION_STEPS[3:]))
        self.assertEqual(initial["request_sha256"], result["request_sha256"])
        self.assertTrue((root / "attestation.json").exists())
        (root / "attestation.json").unlink()
        with mock.patch.object(activation.os, "geteuid", return_value=self.uid):
            resumed = activation.execute_first_adoption_transaction(
                request=request,
                journal_file=journal_path,
                attestation=root / "attestation.json",
                rollback_evidence=root / "rollback.json",
                expected_uid=self.uid,
                runner=mock.Mock(),
                step_handler=lambda *_args, **_kwargs: self.fail(
                    "complete first adoption executed another step"
                ),
            )
        self.assertEqual(resumed, result)
        self.assertEqual(
            resumed["steps"]["validated"]["port_reservation_rows"],
            retained_port_rows,
        )
        self.assertEqual(
            resumed["steps"]["complete"]["port_reservations_sha256"],
            port_bundle["document_sha256"],
        )
        recorded_attestation = cutover.read_private_json(
            root / "attestation.json", uid=self.uid
        )
        self.assertEqual(
            recorded_attestation["steps"]["validated"],
            resumed["steps"]["validated"],
        )
        self.assertEqual(
            recorded_attestation["steps"]["complete"],
            resumed["steps"]["complete"],
        )
        self.assertEqual(
            recorded_attestation["kind"],
            activation.FIRST_ADOPTION_ATTESTATION_KIND,
        )

        reverse_journal = root / "reverse-journal.json"
        reverse = activation._write_first_adoption_transaction(
            reverse_journal,
            {
                "transaction_id": str(uuid.uuid4()),
                "request_sha256": request["document_sha256"],
                "phase": "validated",
                "steps": {"validated": {"ok": True}},
                "created_at": activation._now(),
                "updated_at": activation._now(),
            },
            expected_uid=self.uid,
        )
        crashed = False

        def crash_reverse(stage: str) -> None:
            nonlocal crashed
            if (
                stage == "first-adoption-rollback-before-journal:graph"
                and not crashed
            ):
                crashed = True
                raise activation.PowerLossSimulation(stage)

        with (
            mock.patch.object(
                cutover,
                "load_state",
                return_value={
                    "release": str(self.release),
                    "phase": "sealed",
                    "evidence": {},
                    "state_generation": 1,
                },
            ),
            self.assertRaises(activation.PowerLossSimulation),
        ):
            activation._resume_first_adoption_rollback(
                current=reverse,
                checked=request,
                journal_file=reverse_journal,
                rollback_evidence=root / "reverse-rollback.json",
                expected_uid=self.uid,
                runner=mock.Mock(),
                failure={"failed_phase": "validated", "error": "synthetic"},
                failpoint=crash_reverse,
            )
        interrupted = activation._load_first_adoption_transaction(
            reverse_journal, expected_uid=self.uid
        )
        self.assertEqual(interrupted["phase"], "rolling_back")
        self.assertNotIn("graph", interrupted["rollback_steps"])
        with (
            mock.patch.object(
                cutover,
                "load_state",
                return_value={
                    "release": str(self.release),
                    "phase": "sealed",
                    "evidence": {},
                    "state_generation": 1,
                },
            ),
            mock.patch.object(activation.os, "geteuid", return_value=self.uid),
            self.assertRaisesRegex(
                activation.ActivationError, "completed its rollback"
            ),
        ):
            activation.execute_first_adoption_transaction(
                request=request,
                journal_file=reverse_journal,
                attestation=root / "reverse-attestation.json",
                rollback_evidence=root / "reverse-rollback.json",
                expected_uid=self.uid,
                runner=mock.Mock(),
                step_handler=lambda *_args, **_kwargs: self.fail(
                    "rollback replay executed a forward step"
                ),
            )
        completed_reverse = activation._load_first_adoption_transaction(
            reverse_journal, expected_uid=self.uid
        )
        self.assertEqual(completed_reverse["phase"], "rolled_back")
        self.assertEqual(
            set(completed_reverse["rollback_steps"]),
            set(activation.FIRST_ADOPTION_ROLLBACK_STEPS),
        )

    def test_first_adoption_rollback_evidence_recovers_from_complete_journal(self) -> None:
        root = private_dir(self.root / "rollback-recovery")
        rollback = cutover.seal(
            activation.FIRST_ADOPTION_ROLLBACK_RESULT_KIND,
            {
                "transaction_id": str(uuid.uuid4()),
                "request_sha256": "a" * 64,
                "failed_phase": "fleet_ready",
                "error": "synthetic failure",
                "rollback_errors": [],
                "rolled_back_at": activation._now(),
            },
        )
        journal = activation._write_first_adoption_transaction(
            root / "journal.json",
            {
                "transaction_id": rollback["transaction_id"],
                "request_sha256": "a" * 64,
                "phase": "rolled_back",
                "steps": {},
                "rollback": rollback,
                "rollback_sha256": rollback["document_sha256"],
                "created_at": activation._now(),
                "updated_at": activation._now(),
            },
            expected_uid=self.uid,
        )
        evidence = root / "rollback.json"
        first = activation._publish_first_adoption_rollback(
            current=journal,
            rollback_evidence=evidence,
            expected_uid=self.uid,
        )
        evidence.unlink()
        second = activation._publish_first_adoption_rollback(
            current=journal,
            rollback_evidence=evidence,
            expected_uid=self.uid,
        )
        self.assertEqual(first, second)
        self.assertEqual(
            cutover.read_private_json(evidence, uid=self.uid), rollback
        )

    def test_notification_handoff_rollback_removes_only_fenced_exact_copy(self) -> None:
        root = private_dir(self.root / "notification-rollback")
        operation_id = str(uuid.uuid4())
        payload = b'{"bots":[]}\n'
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        source = private_file(root / "source.json", payload)
        destination = private_file(root / "destination.json", payload)
        rollback = private_file(root / "rollback.json", payload, 0o400)
        fence = private_file(
            root / "fence.json",
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": "devcoordinator-notification-writer-fence",
                    "deployment_id": operation_id,
                    "captured_at": activation._now(),
                    "legacy_writer_unit": "devops-console.service",
                    "legacy_writer_inactive": True,
                    "source_path": str(source),
                    "source_sha256": digest,
                },
                sort_keys=True,
            ).encode(),
        )
        journal = {
            "operation_id": operation_id,
            "legacy_stop_handoff": {
                "ok": True,
                "kind": "devcoordinator-notification-state-handoff",
                "deployment_id": operation_id,
                "source_sha256": digest,
                "destination": str(destination),
                "rollback": str(rollback),
                "legacy_writer_fenced": True,
            },
        }
        result = activation._rollback_notification_state_handoff(
            journal,
            background={
                "telegram_source": str(source),
                "telegram_destination": str(destination),
                "telegram_rollback": str(rollback),
                "telegram_fence": str(fence),
                "destination_owner_uid": self.uid,
            },
            runner=FirewallRunner(),
            expected_uid=self.uid,
        )
        self.assertEqual(
            result["removed"], sorted(map(str, (destination, rollback, fence)))
        )
        self.assertTrue(source.exists())
        self.assertFalse(destination.exists())
        self.assertFalse(rollback.exists())
        self.assertFalse(fence.exists())

    def test_host_preflight_rejects_stale_forged_and_wrong_release_evidence(self) -> None:
        valid = host_preflight_document(self.release)
        with mock.patch.object(activation, "IMMUTABLE_RELEASE_ROOT", self.release_root):
            verified = activation.verify_host_preflight(valid, release=self.release)
            self.assertEqual(verified["release_digest"], DIGEST)

            stale_unsigned = {
                key: value
                for key, value in valid.items()
                if key not in {"schema_version", "kind", "document_sha256", "observed_at"}
            }
            stale = cutover.seal(
                activation.HOST_PREFLIGHT_KIND,
                {**stale_unsigned, "observed_at": "2020-01-01T00:00:00.000Z"},
            )
            with self.assertRaisesRegex(activation.ActivationError, "stale"):
                activation.verify_host_preflight(stale, release=self.release)

            forged = dict(valid)
            forged["release_digest"] = "e" * 64
            with self.assertRaisesRegex(cutover.CutoverError, "digest"):
                activation.verify_host_preflight(forged, release=self.release)

            wrong_unsigned = {
                key: value
                for key, value in valid.items()
                if key not in {"schema_version", "kind", "document_sha256", "release_digest"}
            }
            wrong = cutover.seal(
                activation.HOST_PREFLIGHT_KIND,
                {**wrong_unsigned, "release_digest": "e" * 64},
            )
            with self.assertRaisesRegex(activation.ActivationError, "binding"):
                activation.verify_host_preflight(wrong, release=self.release)

            incomplete_unsigned = {
                key: value
                for key, value in valid.items()
                if key
                not in {
                    "schema_version",
                    "kind",
                    "document_sha256",
                    "checks",
                }
            }
            incomplete = cutover.seal(
                activation.HOST_PREFLIGHT_KIND,
                {
                    **incomplete_unsigned,
                    "checks": [
                        check
                        for check in valid["checks"]
                        if check["id"] != "host-loopback-nonloopback-denied"
                    ],
                },
            )
            with self.assertRaisesRegex(activation.ActivationError, "omitted"):
                activation.verify_host_preflight(
                    incomplete,
                    release=self.release,
                )

    def test_first_adoption_preflight_records_missing_handoff_contract(self) -> None:
        binary_root = private_dir(self.root / "xtables")
        backend = private_file(binary_root / "xtables-nft-multi", b"binary\n", 0o700)
        binaries = {}
        for name in activation.XTABLES_BINARIES:
            link = binary_root / name
            link.symlink_to(backend)
            binaries[name] = link
        rendered = private_dir(self.root / "handoff-rendered")
        result = activation.first_adoption_handoff_preflight(
            rendered_units=rendered,
            publication_file=self.publication_file,
            http_handoff_port=38080,
            https_handoff_port=38443,
            expected_uid=self.uid,
            runner=FirewallRunner(),
            binaries=binaries,
        )
        self.assertFalse(result["ready"])
        self.assertIn("temporary-edge-socket-contract-missing", result["blockers"])
        self.assertFalse(result["mutated_firewall"])

    def test_public_handoff_redirect_resumes_only_its_exact_owned_chain(self) -> None:
        runner = EdgeFirewallRunner()
        operation_id = str(uuid.uuid4())
        binaries = {
            "iptables": Path("/usr/sbin/iptables"),
            "iptables-save": Path("/usr/sbin/iptables-save"),
            "ip6tables": Path("/usr/sbin/ip6tables"),
            "ip6tables-save": Path("/usr/sbin/ip6tables-save"),
        }
        for family in ("ipv4", "ipv6"):
            baseline = activation._ruleset_evidence(
                family, runner=runner, binaries=binaries
            )
            first = activation._apply_redirect_family(
                family,
                operation_id=operation_id,
                http_port=38080,
                https_port=38443,
                baseline_unrelated_sha256=baseline["unrelated_sha256"],
                runner=runner,
                binaries=binaries,
            )
            resumed = activation._apply_redirect_family(
                family,
                operation_id=operation_id,
                http_port=38080,
                https_port=38443,
                baseline_unrelated_sha256=baseline["unrelated_sha256"],
                runner=runner,
                binaries=binaries,
            )
            self.assertEqual(first, resumed)
            self.assertEqual(len(runner.rules[family]), 4)
            self.assertTrue(
                activation._handoff_chain_owned(
                    runner.text([str(binaries[f"ip{'' if family == 'ipv4' else '6'}tables-save"]), "-t", "nat"]),
                    operation_id=operation_id,
                )
            )
            with self.assertRaisesRegex(
                activation.ActivationError, "another contract"
            ):
                activation._apply_redirect_family(
                    family,
                    operation_id=str(uuid.uuid4()),
                    http_port=38080,
                    https_port=38443,
                    baseline_unrelated_sha256=baseline["unrelated_sha256"],
                    runner=runner,
                    binaries=binaries,
                )
            self.assertIn(
                "-A FOREIGN -j ACCEPT",
                runner.text(
                    [
                        str(
                            binaries[
                                "iptables-save"
                                if family == "ipv4"
                                else "ip6tables-save"
                            ]
                        ),
                        "-t",
                        "nat",
                    ]
                ),
            )

    def test_completed_public_handoff_replays_exact_continuity_evidence(
        self,
    ) -> None:
        continuity = activation.ContinuityProbeSession(
            release_digest=DIGEST,
            urls=("https://console.example/healthz",),
            http_probe=lambda _url: (200, False),
            websocket_probe=lambda _url: (200, False),
        ).start().finish()
        journal = self.root / "public-handoff-replay.json"
        expected = activation._write_journal(
            journal,
            {
                "release_digest": DIGEST,
                "phase": "complete",
                "continuity_probe": continuity,
                "completed_at": activation._now(),
            },
            expected_uid=self.uid,
        )
        arguments = {
            "release": self.release,
            "rendered_units": self.root / "unused-rendered",
            "publication_file": self.root / "unused-publication.json",
            "publication_input": None,
            "journal_file": journal,
            "http_handoff_port": 38080,
            "https_handoff_port": 38443,
            "edge_uid": self.uid,
            "edge_gid": os.getegid(),
            "expected_uid": self.uid,
        }
        with mock.patch.object(
            activation, "IMMUTABLE_RELEASE_ROOT", self.release_root
        ):
            replay = activation.first_adoption_handoff(**arguments)
            self.assertEqual(replay, expected)

            invalid = cutover.seal(
                cutover.CONTINUITY_PROBE_KIND,
                {
                    key: value
                    for key, value in continuity.items()
                    if key
                    not in {
                        "schema_version",
                        "kind",
                        "document_sha256",
                        "passed",
                    }
                }
                | {"passed": False},
            )
            activation._write_journal(
                journal,
                {
                    "release_digest": DIGEST,
                    "phase": "complete",
                    "continuity_probe": invalid,
                    "completed_at": expected["completed_at"],
                },
                expected_uid=self.uid,
            )
            with self.assertRaisesRegex(
                activation.ActivationError, "continuity evidence"
            ):
                activation.first_adoption_handoff(**arguments)

    def test_api_handoff_redirect_is_exact_and_reversible(self) -> None:
        runner = ApiFirewallRunner()
        operation_id = str(uuid.uuid4())
        listeners = {39076: 501, 29876: 502}
        started = activation.start_api_handoff(
            handoff_port=39076,
            operation_id=operation_id,
            runner=runner,
            listener_reader=lambda port: listeners[port],
            api_probe=lambda _port: 200,
            binaries={
                **activation.XTABLES_BINARIES,
                "iptables": Path("/usr/sbin/iptables"),
                "iptables-save": Path("/usr/sbin/iptables-save"),
            },
        )
        self.assertTrue(runner.chain)
        self.assertEqual(started["handoff_socket_inode"], 501)
        finished = activation.finish_api_handoff(
            started,
            runner=runner,
            listener_reader=lambda port: listeners[port],
            api_probe=lambda _port: 200,
            binaries={
                **activation.XTABLES_BINARIES,
                "iptables": Path("/usr/sbin/iptables"),
                "iptables-save": Path("/usr/sbin/iptables-save"),
            },
        )
        self.assertFalse(runner.chain)
        self.assertEqual(finished["final_socket_inode"], 502)
        self.assertIn(
            ("enable", "--now", "devcoordinator-api.socket"), runner.systemd
        )

    def test_retained_inventory_gate_requires_nonempty_repository_set(self) -> None:
        module_source = (
            ROOT
            / "skills/codex-dev-coordinator/scripts/devcoordinator/inventory_projection.py"
        )
        module_destination = (
            self.release
            / "skills/codex-dev-coordinator/scripts/devcoordinator/inventory_projection.py"
        )
        module_destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(module_source, module_destination)
        module_destination.chmod(0o444)
        inventory_root = private_dir(self.root / "inventory")
        database = inventory_root / "inventory.sqlite3"
        publication_path = inventory_root / "inventory.publication"
        value = inventory_envelope(
            generation=1,
            published_at="2026-07-28T00:00:00.000Z",
            inventory={
                "schema_version": 1,
                "repositories": [{"id": "repo-alpha"}],
                "servers": [],
                "docker": {"available": True, "containers": []},
                "project_usage": [],
                "projection_status": "retained",
            },
        )
        initialize_inventory_store(
            database,
            value,
            owner_uid=self.uid,
            owner_gid=os.getegid(),
        )
        publish_projection(
            publication_path,
            value,
            owner_uid=self.uid,
            owner_gid=os.getegid(),
        )
        with mock.patch.object(
            activation, "IMMUTABLE_RELEASE_ROOT", self.release_root
        ):
            verified = activation.verify_nonempty_retained_inventory(
                release=self.release,
                database=database,
                publication=publication_path,
                observer_uid=self.uid,
            )
        self.assertEqual(verified["repository_count"], 1)

    def test_retained_route_gate_requires_checksum_valid_nonempty_routes(self) -> None:
        current = json.loads(self.publication_file.read_text())
        current["payload_sha256"] = activation._sha256_bytes(
            activation._canonical(current["publication"])
        )
        self.publication_file.write_text(json.dumps(current), encoding="utf-8")
        self.publication_file.chmod(0o600)
        verified = activation.verify_nonempty_retained_routes(self.publication_file)
        self.assertEqual(verified["route_count"], 1)
        current["publication"]["routes"] = {}
        current["payload_sha256"] = activation._sha256_bytes(
            activation._canonical(current["publication"])
        )
        self.publication_file.write_text(json.dumps(current), encoding="utf-8")
        self.publication_file.chmod(0o600)
        with self.assertRaisesRegex(activation.ActivationError, "empty"):
            activation.verify_nonempty_retained_routes(self.publication_file)

    def test_publication_probes_exclude_only_exact_unavailable_routes(self) -> None:
        current = json.loads(self.publication_file.read_text())
        current["publication"]["routes"] = {
            "available": {"upstream": {}},
            "offline": {
                "upstream": {
                    "status": "unavailable",
                    "scheme": "https",
                    "tls_server_name": "offline.vr.ae",
                    "tls_verify": True,
                }
            },
        }
        self.assertEqual(
            activation._publication_probes(current),
            [
                "https://console.vr.ae/healthz",
                "https://available.vr.ae/",
            ],
        )
        current["publication"]["routes"]["offline"]["upstream"][
            "unexpected"
        ] = True
        with self.assertRaisesRegex(
            activation.ActivationError,
            "unavailable-route protocol",
        ):
            activation._publication_probes(current)
        del current["publication"]["routes"]["offline"]["upstream"][
            "unexpected"
        ]
        current["publication"]["routes"]["offline"]["upstream"][
            "tls_server_name"
        ] = "not a dns name"
        with self.assertRaisesRegex(
            activation.ActivationError,
            "unavailable-route protocol",
        ):
            activation._publication_probes(current)

    def test_continuity_collector_seals_http_and_websocket_samples(self) -> None:
        session = activation.ContinuityProbeSession(
            release_digest=DIGEST,
            urls=[
                "https://console.vr.ae/healthz",
                "https://project.vr.ae/",
            ],
            http_probe=lambda _url: (200, False),
            websocket_probe=lambda _url: (101, False),
            sample_interval_ms=10_000,
        ).start()
        evidence = session.finish()
        self.assertTrue(evidence["passed"])
        self.assertGreaterEqual(evidence["round_count"], 2)
        self.assertGreater(evidence["http_sample_count"], 0)
        self.assertGreater(evidence["websocket_sample_count"], 0)
        self.assertEqual(evidence["connection_refused_count"], 0)
        self.assertEqual(evidence["project_route_failures"], 0)
        self.assertEqual(
            activation.cutover._continuity_probe(
                evidence, expected_release=DIGEST
            ),
            evidence,
        )

    def test_continuity_collector_fails_closed_on_websocket_refusal(self) -> None:
        session = activation.ContinuityProbeSession(
            release_digest=DIGEST,
            urls=[
                "https://console.vr.ae/healthz",
                "https://project.vr.ae/",
            ],
            http_probe=lambda _url: (200, False),
            websocket_probe=lambda _url: (None, True),
            sample_interval_ms=10_000,
        ).start()
        with self.assertRaisesRegex(activation.ActivationError, "sealed SLO"):
            session.finish()

    def test_activation_is_immutable_evidence_gated_and_listener_preserving(self) -> None:
        events: list[str] = []

        def fetched(url, timeout):
            events.append("oidc")
            return oidc(url, timeout)

        runner = FakeRunner(self.publication_file, events)
        with mock.patch.object(activation, "IMMUTABLE_RELEASE_ROOT", self.release_root):
            evidence, credentials = activation.activate(
                state=self.state,
                publication_file=self.publication_file,
                candidate_control=Path("/candidate.sock"),
                previous_control=Path("/previous.sock"),
                credentials=self.credentials,
                expected_uid=self.uid,
                runner=runner,
                oidc_fetcher=fetched,
                socket_reader=lambda: dict(self.sockets),
                probe=lambda _url: (200, False),
                continuity_probe=lambda _url: (200, False),
            )
        evidence = activation.finalize_browser_bound_activation(
            state=self.state,
            pending_activation=evidence,
            browser_binding={
                "browser_lcp_attestation_sha256": "7" * 64,
                "browser_lcp_consumption_sha256": "8" * 64,
            },
        )
        self.assertEqual(events[0], "oidc")
        self.assertEqual(evidence["publication_switch"]["generation"], 8)
        self.assertEqual(evidence["socket_inodes_before"], evidence["socket_inodes_after"])
        self.assertEqual(evidence["credential_preflight_sha256"], credentials["document_sha256"])
        self.assertTrue(evidence["continuity_probe"]["passed"])
        self.assertGreaterEqual(evidence["continuity_probe"]["round_count"], 2)
        self.assertGreater(
            evidence["continuity_probe"]["websocket_sample_count"], 0
        )
        self.assertEqual(json.loads(self.publication_file.read_text())["publication"]["release_digest"], DIGEST)

    def test_activation_switch_journal_recovers_power_loss_and_replays_complete(self) -> None:
        for index, crash_stage in enumerate(
            (
                "promotion_after_effect_before_journal",
                "publication_after_effect_before_journal",
            )
        ):
            with self.subTest(crash_stage=crash_stage):
                publication(self.publication_file)
                runner = FakeRunner(self.publication_file, [])
                journal = private_dir(self.root / "activation-switch") / (
                    f"switch-{index}.json"
                )
                triggered = False

                def failpoint(stage: str) -> None:
                    nonlocal triggered
                    if not triggered and stage == crash_stage:
                        triggered = True
                        raise activation.PowerLossSimulation(stage)

                arguments = {
                    "state": self.state,
                    "publication_file": self.publication_file,
                    "candidate_control": Path("/candidate.sock"),
                    "previous_control": Path("/previous.sock"),
                    "credentials": self.credentials,
                    "expected_uid": self.uid,
                    "runner": runner,
                    "oidc_fetcher": oidc,
                    "socket_reader": lambda: dict(self.sockets),
                    "probe": lambda _url: (200, False),
                    "continuity_probe": lambda _url: (200, False),
                    "switch_journal": journal,
                }
                with (
                    mock.patch.object(
                        activation, "IMMUTABLE_RELEASE_ROOT", self.release_root
                    ),
                    self.assertRaises(activation.PowerLossSimulation),
                ):
                    activation.activate(**arguments, failpoint=failpoint)
                self.assertTrue(triggered)
                interrupted = activation._load_private_journal(
                    journal,
                    kind=activation.ACTIVATION_SWITCH_JOURNAL_KIND,
                    expected_uid=self.uid,
                )
                self.assertIsNotNone(interrupted)
                self.assertNotEqual(interrupted["phase"], "complete")

                with mock.patch.object(
                    activation, "IMMUTABLE_RELEASE_ROOT", self.release_root
                ):
                    evidence, credentials = activation.activate(**arguments)
                completed = activation._load_private_journal(
                    journal,
                    kind=activation.ACTIVATION_SWITCH_JOURNAL_KIND,
                    expected_uid=self.uid,
                )
                self.assertEqual(completed["phase"], "complete")
                self.assertEqual(completed["recovery_count"], 1)
                self.assertEqual(completed["pending_activation"], evidence)
                self.assertEqual(
                    json.loads(self.publication_file.read_text())["publication"][
                        "release_digest"
                    ],
                    DIGEST,
                )
                self.assertEqual(runner.modes["/candidate.sock"], "active")

                mutations = runner.mutation_count
                with mock.patch.object(
                    activation, "IMMUTABLE_RELEASE_ROOT", self.release_root
                ):
                    replay, replay_credentials = activation.activate(**arguments)
                self.assertEqual(replay, evidence)
                self.assertEqual(replay_credentials, credentials)
                self.assertEqual(runner.mutation_count, mutations)

    def test_activate_cli_publishes_exact_continuity_evidence(self) -> None:
        root = private_dir(self.root / "activate-cli-continuity")
        continuity = activation.ContinuityProbeSession(
            release_digest=DIGEST,
            urls=("https://console.example/healthz",),
            http_probe=lambda _url: (200, False),
            websocket_probe=lambda _url: (200, False),
        ).start().finish()
        activation_document = {
            "document_sha256": "a" * 64,
            "continuity_probe": continuity,
        }
        pending_document = {
            "document_sha256": "c" * 64,
            "continuity_probe": continuity,
            "publication_switch": {"generation": 8},
        }
        credential_document = {"document_sha256": "b" * 64}
        activation_path = root / "activation.json"
        continuity_path = root / "continuity.json"
        credential_path = root / "credential.json"
        output = io.StringIO()
        with (
            mock.patch.object(
                cutover,
                "load_state",
                return_value={
                    "release": str(self.release),
                    "cutover_id": str(uuid.uuid4()),
                },
            ),
            mock.patch.object(
                activation,
                "activate",
                return_value=(
                    pending_document,
                    credential_document,
                ),
            ),
            mock.patch.object(
                activation,
                "bind_browser_lcp_acceptance",
                return_value={
                    "browser_lcp_attestation_sha256": "7" * 64,
                    "browser_lcp_consumption_sha256": "8" * 64,
                },
            ),
            mock.patch.object(
                activation,
                "finalize_browser_bound_activation",
                return_value=activation_document,
            ),
            mock.patch.object(
                cutover,
                "record_evidence",
                return_value={"phase": "activated"},
            ),
            redirect_stdout(output),
        ):
            result = activation.main(
                [
                    "activate",
                    "--state",
                    str(root / "state.json"),
                    "--publication",
                    str(root / "publication.json"),
                    "--candidate-control",
                    str(root / "candidate.sock"),
                    "--previous-control",
                    str(root / "previous.sock"),
                    "--activation-evidence",
                    str(activation_path),
                    "--continuity-evidence",
                    str(continuity_path),
                    "--credential-evidence",
                    str(credential_path),
                    "--browser-runtime-lock",
                    str(root / "runtime-lock.json"),
                    "--browser-storage-state",
                    str(root / "storage-state.json"),
                    "--browser-signing-key",
                    str(root / "signing-key"),
                    "--browser-journal",
                    str(root / "browser-journal.json"),
                    "--browser-attestation",
                    str(root / "browser-attestation.json"),
                    "--browser-consumption",
                    str(root / "browser-consumption.json"),
                    "--authority-uid",
                    str(self.uid),
                ]
            )
        self.assertEqual(result, 0)
        self.assertEqual(
            cutover.read_private_json(
                continuity_path, uid=self.uid
            ),
            continuity,
        )
        self.assertEqual(
            cutover.read_private_json(
                activation_path, uid=self.uid
            ),
            activation_document,
        )
        response = json.loads(output.getvalue())
        self.assertEqual(
            response["continuity_evidence"], str(continuity_path)
        )

    def _activated_live_rehearsal_fixture(
        self,
    ) -> tuple[dict[str, object], FakeRunner]:
        publication(self.publication_file)
        runner = FakeRunner(self.publication_file, [])
        with mock.patch.object(
            activation, "IMMUTABLE_RELEASE_ROOT", self.release_root
        ):
            evidence, _credential = activation.activate(
                state=self.state,
                publication_file=self.publication_file,
                candidate_control=Path("/candidate.sock"),
                previous_control=Path("/previous.sock"),
                credentials=self.credentials,
                expected_uid=self.uid,
                runner=runner,
                oidc_fetcher=oidc,
                socket_reader=lambda: dict(self.sockets),
                probe=lambda _url: (200, False),
                continuity_probe=lambda _url: (200, False),
            )
        evidence = activation.finalize_browser_bound_activation(
            state=self.state,
            pending_activation=evidence,
            browser_binding={
                "browser_lcp_attestation_sha256": "7" * 64,
                "browser_lcp_consumption_sha256": "8" * 64,
            },
        )
        return (
            cutover.transition(
                self.state, evidence_kind="activation", evidence=evidence
            ),
            runner,
        )

    def _run_live_rehearsal(
        self,
        *,
        state: Mapping[str, object],
        runner: FakeRunner,
        journal: Path,
        continuity_probe=lambda _url: (200, False),
        profile_health=lambda: {"ready": True, "sha256": "a" * 64},
        failpoint=None,
    ) -> dict[str, object]:
        return activation.rehearse_live_traffic_rollback(
            state=state,
            publication_file=self.publication_file,
            candidate_control=Path("/candidate.sock"),
            previous_control=Path("/previous.sock"),
            journal_file=journal,
            expected_uid=self.uid,
            runner=runner,
            socket_reader=lambda: dict(self.sockets),
            probe=lambda _url: (200, False),
            continuity_probe=continuity_probe,
            profile_health=profile_health,
            data_health=lambda: {"ready": True, "stores": {}},
            failpoint=failpoint,
        )

    def test_live_rollback_rehearsal_reverses_and_reactivates_under_continuous_probes(
        self,
    ) -> None:
        state, runner = self._activated_live_rehearsal_fixture()
        evidence = self._run_live_rehearsal(
            state=state,
            runner=runner,
            journal=self.root / "live-success.json",
        )
        verified = cutover.transition(
            state,
            evidence_kind="live-rollback-rehearsal",
            evidence=evidence,
        )
        self.assertIn("live-rollback-rehearsal", verified["evidence"])
        self.assertTrue(evidence["continuity_probe"]["passed"])
        self.assertTrue(evidence["rollback_continuity_probe"]["passed"])
        self.assertTrue(evidence["reactivation_continuity_probe"]["passed"])
        self.assertEqual(
            evidence["supported_rollback_head"],
            evidence["publication_reactivated"],
        )
        self.assertEqual(
            evidence["rollback_switch"]["previous_payload_sha256"],
            evidence["publication_before"]["payload_sha256"],
        )
        self.assertEqual(
            evidence["reactivation_switch"]["previous_payload_sha256"],
            evidence["publication_rollback"]["payload_sha256"],
        )
        self.assertEqual(runner.modes["/candidate.sock"], "active")
        self.assertEqual(
            json.loads(self.publication_file.read_text())["publication"][
                "release_digest"
            ],
            DIGEST,
        )

    def test_live_rehearsal_power_loss_boundaries_recover_then_repeat_full_attempt(
        self,
    ) -> None:
        stages = (
            "planned",
            "rollback_slot_intent",
            "rollback-slot-after-effect-before-journal",
            "rollback_slot_ready",
            "rollback_publication_intent",
            "rollback-publication-after-effect-before-journal",
            "rollback_ready",
            "reactivation_slot_intent",
            "reactivation-slot-after-effect-before-journal",
            "reactivation_slot_ready",
            "reactivation_publication_intent",
            "reactivation-publication-after-effect-before-journal",
            "reactivated",
            "complete",
        )
        for index, stage in enumerate(stages):
            with self.subTest(stage=stage):
                state, runner = self._activated_live_rehearsal_fixture()
                journal = self.root / f"live-crash-{index}.json"
                triggered = False

                def failpoint(observed: str) -> None:
                    nonlocal triggered
                    if not triggered and observed == stage:
                        triggered = True
                        raise activation.PowerLossSimulation(stage)

                with self.assertRaises(activation.PowerLossSimulation):
                    self._run_live_rehearsal(
                        state=state,
                        runner=runner,
                        journal=journal,
                        failpoint=failpoint,
                    )
                self.assertTrue(triggered)
                evidence = self._run_live_rehearsal(
                    state=state,
                    runner=runner,
                    journal=journal,
                )
                cutover.transition(
                    state,
                    evidence_kind="live-rollback-rehearsal",
                    evidence=evidence,
                )
                self.assertEqual(runner.modes["/candidate.sock"], "active")
                self.assertTrue(evidence["continuity_probe"]["passed"])
                if stage not in {"planned", "complete"}:
                    self.assertGreaterEqual(evidence["recovery_count"], 1)

    def test_live_rehearsal_probe_failure_recovers_candidate_and_replays(
        self,
    ) -> None:
        state, runner = self._activated_live_rehearsal_fixture()
        journal = self.root / "live-probe-failure.json"
        with self.assertRaisesRegex(
            activation.ActivationError, "activated candidate restored"
        ):
            self._run_live_rehearsal(
                state=state,
                runner=runner,
                journal=journal,
                continuity_probe=lambda _url: (503, False),
            )
        self.assertEqual(runner.modes["/candidate.sock"], "active")
        self.assertEqual(
            json.loads(self.publication_file.read_text())["publication"][
                "release_digest"
            ],
            DIGEST,
        )
        evidence = self._run_live_rehearsal(
            state=state,
            runner=runner,
            journal=journal,
        )
        self.assertGreaterEqual(evidence["recovery_count"], 1)

    def test_live_rehearsal_completed_journal_replays_without_mutation(self) -> None:
        state, runner = self._activated_live_rehearsal_fixture()
        journal = self.root / "live-replay.json"
        evidence = self._run_live_rehearsal(
            state=state,
            runner=runner,
            journal=journal,
        )
        mutations = runner.mutation_count
        replay = self._run_live_rehearsal(
            state=state,
            runner=runner,
            journal=journal,
        )
        self.assertEqual(replay, evidence)
        self.assertEqual(runner.mutation_count, mutations)

    def test_live_rehearsal_cli_publishes_and_records_exact_attestation(self) -> None:
        state, _authority, _testd, activation_evidence = fixtures.through_activation()
        document = fixtures.live_rollback_rehearsal(state, activation_evidence)
        root = private_dir(self.root / "live-cli")
        attestation = root / "live.json"
        continuity = root / "continuity.json"
        output = io.StringIO()
        with (
            mock.patch.object(cutover, "load_state", return_value=state),
            mock.patch.object(
                activation,
                "rehearse_live_traffic_rollback",
                return_value=document,
            ),
            mock.patch.object(
                cutover,
                "record_evidence",
                return_value={"phase": "activated", "replayed": False},
            ) as record,
            redirect_stdout(output),
        ):
            result = activation.main(
                [
                    "rehearse-live-rollback",
                    "--state",
                    str(root / "state.json"),
                    "--publication",
                    str(root / "publication.json"),
                    "--candidate-control",
                    str(root / "candidate.sock"),
                    "--previous-control",
                    str(root / "previous.sock"),
                    "--journal",
                    str(root / "journal.json"),
                    "--attestation",
                    str(attestation),
                    "--continuity-evidence",
                    str(continuity),
                    "--authority-uid",
                    str(self.uid),
                ]
            )
        self.assertEqual(result, 0)
        self.assertEqual(cutover.read_private_json(attestation, uid=self.uid), document)
        self.assertEqual(
            cutover.read_private_json(continuity, uid=self.uid),
            document["continuity_probe"],
        )
        self.assertEqual(
            record.call_args.kwargs["evidence_kind"],
            "live-rollback-rehearsal",
        )
        self.assertEqual(
            json.loads(output.getvalue())["supported_rollback_head"],
            document["supported_rollback_head"],
        )

    def test_live_rehearsal_rejects_foreign_publication_generation(self) -> None:
        state, runner = self._activated_live_rehearsal_fixture()
        current = json.loads(self.publication_file.read_text())
        current["publication"]["generation"] += 1
        current["publication"]["published_at"] = "2026-07-28T12:00:00.000Z"
        current["payload_sha256"] = activation._sha256_bytes(
            activation._canonical(current["publication"])
        )
        self.publication_file.write_text(json.dumps(current), encoding="utf-8")
        self.publication_file.chmod(0o600)
        mutations = runner.mutation_count
        with self.assertRaisesRegex(
            activation.ActivationError, "publication head changed"
        ):
            self._run_live_rehearsal(
                state=state,
                runner=runner,
                journal=self.root / "live-foreign.json",
            )
        self.assertEqual(runner.mutation_count, mutations)

    def test_live_rehearsal_rejects_contradictory_root_owned_journal(self) -> None:
        state, runner = self._activated_live_rehearsal_fixture()
        journal = self.root / "live-contradictory.json"

        def failpoint(stage: str) -> None:
            if stage == "rollback_slot_intent":
                raise activation.PowerLossSimulation(stage)

        with self.assertRaises(activation.PowerLossSimulation):
            self._run_live_rehearsal(
                state=state,
                runner=runner,
                journal=journal,
                failpoint=failpoint,
            )
        document = cutover.read_private_json(journal, uid=self.uid)
        payload = {
            key: value
            for key, value in document.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        payload["publication_before"] = dict(payload["publication_before"])
        payload["publication_before"]["generation"] += 7
        activation._write_private_journal(
            journal,
            kind=activation.LIVE_ROLLBACK_REHEARSAL_JOURNAL_KIND,
            payload=payload,
            expected_uid=self.uid,
        )
        with self.assertRaisesRegex(
            activation.ActivationError, "unjournaled publication head"
        ):
            self._run_live_rehearsal(
                state=state,
                runner=runner,
                journal=journal,
            )

    def test_live_rehearsal_rechecks_owner_profile_inventory_at_each_side(self) -> None:
        state, runner = self._activated_live_rehearsal_fixture()
        calls = 0

        def health() -> dict[str, object]:
            nonlocal calls
            calls += 1
            return {
                "ready": True,
                "proof_sha256": f"{calls:064x}",
                "inventory_sha256": f"{calls + 10:064x}",
                "profile_sha256": "a" * 64,
                "authority_generation": fixtures.TARGET_AUTHORITY_GENERATION,
                "project": fixtures.INVENTORY_PROJECT,
                "owner_uid": fixtures.OWNER_UID,
                "repository_id": "repo-alpha",
                "repository_generation": 7,
            }

        evidence = self._run_live_rehearsal(
            state=state,
            runner=runner,
            journal=self.root / "live-profile-canary.json",
            profile_health=health,
        )
        self.assertEqual(calls, 3)
        self.assertEqual(
            {
                evidence["profile_health"][stage]["proof_sha256"]
                for stage in ("before", "rollback", "reactivated")
            },
            {f"{index:064x}" for index in (1, 2, 3)},
        )

    def test_failed_continuity_window_restores_previous_activation(self) -> None:
        runner = FakeRunner(self.publication_file, [])
        with mock.patch.object(
            activation, "IMMUTABLE_RELEASE_ROOT", self.release_root
        ):
            with self.assertRaisesRegex(
                activation.ActivationError,
                "continuity probe.*rolled back|rolled back.*continuity probe",
            ):
                activation.activate(
                    state=self.state,
                    publication_file=self.publication_file,
                    candidate_control=Path("/candidate.sock"),
                    previous_control=Path("/previous.sock"),
                    credentials=self.credentials,
                    expected_uid=self.uid,
                    runner=runner,
                    oidc_fetcher=oidc,
                    socket_reader=lambda: dict(self.sockets),
                    probe=lambda _url: (200, False),
                    continuity_probe=lambda _url: (503, False),
                )
        current = json.loads(self.publication_file.read_text())
        self.assertEqual(
            current["publication"]["release_digest"], OLD_DIGEST
        )
        self.assertEqual(
            current["publication"]["console"]["upstream"]["port"], 30443
        )
        self.assertEqual(runner.modes["/previous.sock"], "active")

    def test_failed_post_switch_probe_restores_previous_slot_and_publication(self) -> None:
        calls = 0

        def probe(_url):
            nonlocal calls
            calls += 1
            # Two URLs are probed before the switch; fail the Console probe in
            # the second pass to force the complete inverse handoff.
            return (503 if calls == 3 else 200), False

        events: list[str] = []
        runner = FakeRunner(self.publication_file, events)
        with mock.patch.object(activation, "IMMUTABLE_RELEASE_ROOT", self.release_root):
            with self.assertRaisesRegex(activation.ActivationError, "rolled back"):
                activation.activate(
                    state=self.state,
                    publication_file=self.publication_file,
                    candidate_control=Path("/candidate.sock"),
                    previous_control=Path("/previous.sock"),
                    credentials=self.credentials,
                    expected_uid=self.uid,
                    runner=runner,
                    oidc_fetcher=oidc,
                    socket_reader=lambda: dict(self.sockets),
                    probe=probe,
                    continuity_probe=lambda _url: (200, False),
                )
        current = json.loads(self.publication_file.read_text())
        self.assertEqual(current["publication"]["release_digest"], OLD_DIGEST)
        self.assertEqual(current["publication"]["console"]["upstream"]["port"], 30443)
        self.assertEqual(runner.modes["/previous.sock"], "active")


if __name__ == "__main__":
    unittest.main()
