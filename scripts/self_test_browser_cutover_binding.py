#!/usr/bin/env python3
"""Focused fail-closed tests for browser evidence cutover/retention binding."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import uuid

import activate_availability_release as activation


DIGEST = "a" * 64


class BrowserCutoverBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.release_root = self.root / "releases"
        self.release_root.mkdir(mode=0o755)
        self.release = self.release_root / DIGEST
        self.release.mkdir(mode=0o555)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir(mode=0o700)
        self.operation_id = str(uuid.uuid4())
        self.uid = os.getuid()
        self.journal = self.evidence / "browser-journal.json"
        self.runtime_lock = self.evidence / "runtime-lock.json"
        self.storage_state = self.evidence / "storage-state.json"
        self.signing_key = self.evidence / "signing-key"
        for path, payload in (
            (self.runtime_lock, b"{}\n"),
            (self.storage_state, b'{"cookies":[{}],"origins":[]}\n'),
            (self.signing_key, b"k" * 32),
        ):
            path.write_bytes(payload)
            path.chmod(0o600)
        self.attestation, self.consumption = activation._browser_cutover_paths(
            self.journal, operation_id=self.operation_id
        )
        self.switch = {
            "previous_generation": 7,
            "generation": 8,
            "previous_payload_sha256": "b" * 64,
            "payload_sha256": "c" * 64,
            "previous_release_digest": "d" * 64,
            "release_digest": DIGEST,
            "previous_port": 30443,
            "port": 31443,
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_marker(self, path: Path) -> None:
        path.write_text("{}\n", encoding="utf-8")
        path.chmod(0o600)

    def _arguments(self) -> dict[str, object]:
        return {
            "release": self.release,
            "operation_id": self.operation_id,
            "publication_switch": self.switch,
            "runtime_lock": self.runtime_lock,
            "storage_state": self.storage_state,
            "signing_key": self.signing_key,
            "journal": self.journal,
            "attestation": self.attestation,
            "consumption": self.consumption,
            "expected_uid": self.uid,
            "expected_gid": os.getgid(),
        }

    def test_uncertain_consumer_reply_recovers_without_second_consumption(self) -> None:
        calls = {"producer": 0, "consumer": 0}

        def producer(**_kwargs):
            calls["producer"] += 1
            self._write_marker(self.attestation)
            return {}

        def verifier(*_args, **_kwargs):
            return {
                "document_sha256": "7" * 64,
                "health": {"generation": 8},
            }

        def consumer(*_args, **_kwargs):
            calls["consumer"] += 1
            self._write_marker(self.consumption)
            raise activation.PowerLossSimulation("consumer reply lost")

        def validate(*_args, **_kwargs):
            return {"document_sha256": "8" * 64}

        with mock.patch.object(
            activation, "IMMUTABLE_RELEASE_ROOT", self.release_root
        ):
            with self.assertRaises(activation.PowerLossSimulation):
                activation.bind_browser_lcp_acceptance(
                    **self._arguments(),
                    producer=producer,
                    verifier=verifier,
                    consumer=consumer,
                    consumption_validator=validate,
                )
            recovered = activation.bind_browser_lcp_acceptance(
                **self._arguments(),
                producer=producer,
                verifier=verifier,
                consumer=consumer,
                consumption_validator=validate,
            )
            replay = activation.bind_browser_lcp_acceptance(
                **self._arguments(),
                producer=producer,
                verifier=verifier,
                consumer=consumer,
                consumption_validator=validate,
            )
        self.assertEqual(calls, {"producer": 1, "consumer": 1})
        self.assertEqual(recovered["browser_lcp_attestation_sha256"], "7" * 64)
        self.assertEqual(recovered["browser_lcp_consumption_sha256"], "8" * 64)
        self.assertEqual(
            replay["browser_lcp_consumption_sha256"],
            recovered["browser_lcp_consumption_sha256"],
        )
        journal = json.loads(self.journal.read_text(encoding="utf-8"))
        self.assertEqual(journal["phase"], "complete")
        self.assertEqual(journal["publication_generation"], 8)
        self.assertEqual(journal["publication_payload_sha256"], "c" * 64)

    def test_browser_failure_is_completion_pending_not_rollback(self) -> None:
        def producer(**_kwargs):
            raise activation.browser_lcp.BrowserLcpAcceptanceError("failed")

        with mock.patch.object(
            activation, "IMMUTABLE_RELEASE_ROOT", self.release_root
        ), self.assertRaisesRegex(
            activation.BrowserAcceptancePending, "remains live"
        ):
            activation.bind_browser_lcp_acceptance(
                **self._arguments(),
                producer=producer,
                verifier=mock.Mock(),
                consumer=mock.Mock(),
            )
        journal = json.loads(self.journal.read_text(encoding="utf-8"))
        self.assertEqual(journal["phase"], "produce_intent")

    def test_recovery_rejects_another_publication_or_evidence_path(self) -> None:
        self._write_marker(self.attestation)
        self._write_marker(self.consumption)
        verifier = lambda *_args, **_kwargs: {
            "document_sha256": "7" * 64,
            "health": {"generation": 8},
        }
        validator = lambda *_args, **_kwargs: {"document_sha256": "8" * 64}
        with mock.patch.object(
            activation, "IMMUTABLE_RELEASE_ROOT", self.release_root
        ):
            activation.bind_browser_lcp_acceptance(
                **self._arguments(),
                producer=mock.Mock(),
                verifier=verifier,
                consumer=mock.Mock(),
                consumption_validator=validator,
            )
            foreign = dict(self._arguments())
            foreign_switch = dict(self.switch)
            foreign_switch["previous_generation"] = 8
            foreign_switch["generation"] = 9
            foreign_switch["previous_payload_sha256"] = "c" * 64
            foreign_switch["payload_sha256"] = "e" * 64
            foreign_switch["previous_release_digest"] = "f" * 64
            foreign_switch["previous_port"] = 31443
            foreign_switch["port"] = 31444
            foreign["publication_switch"] = foreign_switch
            with self.assertRaisesRegex(
                activation.ActivationError, "another cutover"
            ):
                activation.bind_browser_lcp_acceptance(
                    **foreign,
                    producer=mock.Mock(),
                    verifier=verifier,
                    consumer=mock.Mock(),
                    consumption_validator=validator,
                )
            wrong_path = dict(self._arguments())
            wrong_path["consumption"] = self.evidence / "other.json"
            with self.assertRaisesRegex(
                activation.ActivationError, "not deterministic"
            ):
                activation.bind_browser_lcp_acceptance(
                    **wrong_path,
                    producer=mock.Mock(),
                    verifier=verifier,
                    consumer=mock.Mock(),
                    consumption_validator=validator,
                )

    def test_recovery_rejects_changed_browser_inputs(self) -> None:
        def interrupted(stage: str) -> None:
            if stage == "produce_intent":
                raise activation.PowerLossSimulation(stage)

        with mock.patch.object(
            activation, "IMMUTABLE_RELEASE_ROOT", self.release_root
        ), self.assertRaises(activation.PowerLossSimulation):
            activation.bind_browser_lcp_acceptance(
                **self._arguments(),
                producer=mock.Mock(),
                verifier=mock.Mock(),
                consumer=mock.Mock(),
                failpoint=interrupted,
            )
        self.storage_state.write_text(
            '{"cookies":[{"changed":true}],"origins":[]}\n',
            encoding="utf-8",
        )
        self.storage_state.chmod(0o600)
        with mock.patch.object(
            activation, "IMMUTABLE_RELEASE_ROOT", self.release_root
        ), self.assertRaisesRegex(
            activation.ActivationError, "another cutover"
        ):
            activation.bind_browser_lcp_acceptance(
                **self._arguments(),
                producer=mock.Mock(),
                verifier=mock.Mock(),
                consumer=mock.Mock(),
            )


if __name__ == "__main__":
    unittest.main()
