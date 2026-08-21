#!/usr/bin/env python3
"""Focused contract tests for release-bound browser LCP acceptance."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts/browser_lcp_acceptance.py"
SPEC = importlib.util.spec_from_file_location("browser_lcp_acceptance", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)


class BrowserLcpProducerSourceTests(unittest.TestCase):
    def test_tests_readiness_accepts_visible_desktop_or_mobile_repo_control(
        self,
    ) -> None:
        source = (ROOT / acceptance.RELEASE_BROWSER_DRIVER).read_text(
            encoding="utf-8"
        )
        self.assertIn("#tests-body .test-repository-button:visible", source)
        self.assertIn("#tests-body .test-fleet-mobile-row:visible", source)
        self.assertIn(
            "page.waitForSelector(TESTS_REPOSITORY_CONTROL_SELECTOR, "
            "{ state: 'visible' })",
            source,
        )
        self.assertNotIn(
            "waitForSelector('#tests-body .test-repository-button'", source
        )


class BrowserLcpAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.uid = os.getuid()
        self.gid = os.getgid()
        self.private = self.root / "private"
        self.private.mkdir(mode=0o700)
        self.key = b"k" * 32
        self.key_path = self.private / "signing.key"
        self.key_path.write_bytes(self.key)
        self.key_path.chmod(0o600)
        self.runtime_root, self.node, self.browser = self._runtime_fixture()
        self.runtime_lock = acceptance.create_runtime_lock_document(
            node_executable=self.node,
            playwright_runtime_root=self.runtime_root,
            browser_executable=self.browser,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )
        self.runtime_lock_path = self.private / "runtime-lock.json"
        acceptance._publish_private(
            self.runtime_lock_path, self.runtime_lock, uid=self.uid
        )
        self.release = self._release_fixture()
        self.operation_id = str(uuid.uuid4())
        self.consumer_operation_id = str(uuid.uuid4())
        self.release_binding = acceptance.verify_release_binding(
            self.release,
            immutable_root=self.release.parent,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )
        runtime_value, runtime_payload = acceptance._read_private_json(
            self.runtime_lock_path,
            uid=self.uid,
            label="fixture runtime lock",
        )
        self.runtime_payload = runtime_payload
        self.runtime_verified = acceptance.verify_runtime_lock_document(
            runtime_value, expected_uid=self.uid, expected_gid=self.gid
        )
        self.observation = self._observation(self.operation_id)
        self.health = self._health(
            self.release.name,
            generation=7,
            observed_at=acceptance._parse_time(
                self.observation["started_at"], "fixture observation start"
            )
            - timedelta(milliseconds=100),
        )
        self.attestation = acceptance._build_attestation(
            operation_id=self.operation_id,
            release_binding=self.release_binding,
            runtime_lock=self.runtime_verified,
            runtime_lock_payload=self.runtime_payload,
            health=self.health,
            observation=self.observation,
            console_url=acceptance.DEFAULT_CONSOLE_URL,
            tests_url=acceptance.DEFAULT_TESTS_URL,
            signing_key=self.key,
            ttl_seconds=300,
        )
        self.attestation_path = self.private / "acceptance.json"
        acceptance._publish_private(
            self.attestation_path, self.attestation, uid=self.uid
        )

    def tearDown(self) -> None:
        # Immutable fixture directories must be made writable for cleanup.
        for target in sorted(self.root.rglob("*"), reverse=True):
            try:
                if target.is_dir() and not target.is_symlink():
                    target.chmod(0o700)
                elif target.exists() and not target.is_symlink():
                    target.chmod(0o600)
            except OSError:
                pass
        self.root.chmod(0o700)
        self.temporary.cleanup()

    def _write_executable(self, path: Path, output: str) -> None:
        path.write_text(f"#!/bin/sh\nprintf '%s\\n' '{output}'\n", encoding="utf-8")
        path.chmod(0o555)

    def _runtime_fixture(self) -> tuple[Path, Path, Path]:
        node = self.root / "node"
        browser = self.root / "chromium"
        self._write_executable(node, "v20.19.2")
        self._write_executable(browser, "Chromium 142.0.7444.175")
        runtime = self.root / "playwright-runtime"
        (runtime / "node_modules/playwright").mkdir(parents=True)
        (runtime / "node_modules/playwright-core").mkdir(parents=True)
        package = {
            "name": "fixture-browser-runtime",
            "private": True,
            "dependencies": {"playwright": "1.61.1"},
        }
        lock = {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"playwright": "1.61.1"}},
                "node_modules/playwright": {"version": "1.61.1"},
                "node_modules/playwright-core": {"version": "1.61.1"},
            },
        }
        (runtime / "package.json").write_text(json.dumps(package), encoding="utf-8")
        (runtime / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
        (runtime / "node_modules/playwright/index.mjs").write_text(
            "export const chromium = {};\n", encoding="utf-8"
        )
        (runtime / "node_modules/playwright/package.json").write_text(
            json.dumps({"name": "playwright", "version": "1.61.1"}),
            encoding="utf-8",
        )
        (runtime / "node_modules/playwright-core/package.json").write_text(
            json.dumps({"name": "playwright-core", "version": "1.61.1"}),
            encoding="utf-8",
        )
        for target in sorted(runtime.rglob("*"), reverse=True):
            target.chmod(0o555 if target.is_dir() else 0o444)
        runtime.chmod(0o555)
        return runtime, node, browser

    def _release_fixture(self) -> Path:
        immutable_root = self.root / "releases"
        immutable_root.mkdir(mode=0o755)
        payloads = {
            acceptance.RELEASE_PRODUCER.as_posix(): b"#!/bin/sh\nexit 0\n",
            acceptance.RELEASE_PRODUCER_SOURCE.as_posix(): b"# fixture producer\n",
            acceptance.RELEASE_BROWSER_DRIVER.as_posix(): b"// fixture driver\n",
        }
        entries = []
        for relative, payload in sorted(payloads.items()):
            entries.append(
                {
                    "path": relative,
                    "sha256": acceptance._sha256_bytes(payload),
                    "size": len(payload),
                    "mode": "0555" if relative.startswith("bin/") else "0444",
                    "kind": "wrapper" if relative.startswith("bin/") else "source",
                }
            )
        digest = acceptance._release_digest(entries)
        release = immutable_root / digest
        release.mkdir()
        for relative, payload in payloads.items():
            target = release / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            target.chmod(
                int(next(item["mode"] for item in entries if item["path"] == relative), 8)
            )
        manifest = {
            "schema_version": 1,
            "release_digest": digest,
            "release_directory": None,
            "source_identity": {"fixture": True},
            "files": entries,
            "capabilities": {"browser_lcp_acceptance": True},
        }
        manifest_path = release / "release-manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        manifest_path.chmod(0o444)
        for directory in sorted(
            [item for item in release.rglob("*") if item.is_dir()], reverse=True
        ):
            directory.chmod(0o555)
        release.chmod(0o555)
        return release

    def _health(
        self,
        release_digest: str,
        *,
        generation: int,
        observed_at: datetime | None = None,
    ) -> dict[str, object]:
        return {
            "url": "https://console.vr.ae/healthz",
            "status": 200,
            "role": "edge",
            "generation": generation,
            "release_digest": release_digest,
            "response_sha256": "a" * 64,
            "observed_at": acceptance._format_time(
                observed_at or acceptance._now()
            ),
        }

    def _observation(self, operation_id: str) -> dict[str, object]:
        started = acceptance._now() - timedelta(seconds=2)
        completed = acceptance._now() - timedelta(seconds=1)
        observed = acceptance._format_time(started + timedelta(milliseconds=500))
        samples = []
        for viewport in acceptance.REQUIRED_VIEWPORTS:
            samples.extend(
                [
                    {
                        "journey": "console",
                        "url": acceptance.DEFAULT_CONSOLE_URL,
                        "final_url": acceptance.DEFAULT_CONSOLE_URL,
                        "viewport": dict(viewport),
                        "navigation_status": 200,
                        "api_status": None,
                        "authenticated": True,
                        "current_tests": False,
                        "test_delivery_state": None,
                        "state": "authenticated_console_shell",
                        "lcp_ms": float(300 + viewport["width"] / 10),
                        "lcp_entry_count": 2,
                        "observed_at": observed,
                    },
                    {
                        "journey": "tests",
                        "url": acceptance.DEFAULT_TESTS_URL,
                        "final_url": acceptance.DEFAULT_TESTS_URL,
                        "viewport": dict(viewport),
                        "navigation_status": 200,
                        "api_status": 200,
                        "authenticated": True,
                        "current_tests": True,
                        "test_delivery_state": "current",
                        "state": "authenticated_current_tests",
                        "lcp_ms": float(400 + viewport["width"] / 10),
                        "lcp_entry_count": 3,
                        "observed_at": observed,
                    },
                ]
            )
        return {
            "schema_version": 1,
            "kind": acceptance.OBSERVATION_KIND,
            "operation_id": operation_id,
            "playwright_version": "1.61.1",
            "browser_product_version": "142.0.7444.175",
            "console_url": acceptance.DEFAULT_CONSOLE_URL,
            "tests_url": acceptance.DEFAULT_TESTS_URL,
            "samples": samples,
            "started_at": acceptance._format_time(started),
            "completed_at": acceptance._format_time(completed),
        }

    def _observer(self, health_url: str, *, expected_release_digest: str):
        self.assertEqual(health_url, "https://console.vr.ae/healthz")
        self.assertEqual(expected_release_digest, self.release.name)
        return self._health(expected_release_digest, generation=7)

    def _verify(self, path: Path | None = None, **overrides):
        arguments = {
            "release": self.release,
            "immutable_root": self.release.parent,
            "runtime_lock_path": self.runtime_lock_path,
            "signing_key_path": self.key_path,
            "expected_operation_id": self.operation_id,
            "expected_uid": self.uid,
            "expected_gid": self.gid,
            "health_observer": self._observer,
        }
        arguments.update(overrides)
        return acceptance.verify_attestation_file(
            path or self.attestation_path, **arguments
        )

    def _resign(self, document: dict[str, object]) -> dict[str, object]:
        values = {
            key: value
            for key, value in document.items()
            if key
            not in {
                "schema_version",
                "kind",
                "signing_key_id",
                "document_sha256",
                "signature_hmac_sha256",
            }
        }
        return acceptance._signed_attestation(values, signing_key=self.key)

    def _private_document(self, name: str, value: dict[str, object]) -> Path:
        path = self.private / name
        acceptance._publish_private(path, value, uid=self.uid)
        return path

    def _reseal_consumption(
        self, document: dict[str, object], **changes: object
    ) -> dict[str, object]:
        values = {
            key: value
            for key, value in document.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        values.update(changes)
        return acceptance._seal_digest(acceptance.CONSUMPTION_KIND, values)

    def _consume(self, output: Path) -> dict[str, object]:
        return acceptance.consume_attestation(
            self.attestation_path,
            consumption_output=output,
            consumer_operation_id=self.consumer_operation_id,
            release=self.release,
            immutable_root=self.release.parent,
            runtime_lock_path=self.runtime_lock_path,
            signing_key_path=self.key_path,
            expected_operation_id=self.operation_id,
            expected_uid=self.uid,
            expected_gid=self.gid,
            health_observer=self._observer,
        )

    def _validate_consumption(
        self,
        document: dict[str, object],
        *,
        now: datetime | None = None,
    ) -> dict[str, object]:
        return acceptance.validate_consumption_document(
            document,
            attestation=self.attestation,
            expected_consumer_operation_id=self.consumer_operation_id,
            expected_release_digest=self.release.name,
            now=now or acceptance._now(),
        )

    def test_valid_attestation_binds_all_required_viewports_and_states(self) -> None:
        result = self._verify()
        self.assertEqual(result["summary"]["sample_count"], 10)
        self.assertEqual(
            result["summary"]["viewport_widths"], [320, 390, 768, 981, 1440]
        )
        self.assertTrue(result["summary"]["all_tests_retained"])
        self.assertLess(result["summary"]["maximum_lcp_ms"], 1000)
        encoded = acceptance._canonical(result)
        self.assertNotIn(self.key, encoded)
        self.assertNotIn(b'"cookies"', encoded)
        self.assertNotIn(b'"storage_state"', encoded)

    def test_forged_payload_fails_hmac_even_with_valid_json(self) -> None:
        forged = json.loads(json.dumps(self.attestation))
        forged["samples"][0]["lcp_ms"] = 1
        path = self._private_document("forged.json", forged)
        with self.assertRaisesRegex(
            acceptance.BrowserLcpAcceptanceError, "signature"
        ):
            self._verify(path)

    def test_partial_samples_fail_even_when_resigned(self) -> None:
        partial = json.loads(json.dumps(self.attestation))
        partial["samples"].pop()
        partial = self._resign(partial)
        path = self._private_document("partial.json", partial)
        with self.assertRaisesRegex(
            acceptance.BrowserLcpAcceptanceError, "samples are incomplete"
        ):
            self._verify(path)

    def test_threshold_is_strictly_below_one_second(self) -> None:
        slow = json.loads(json.dumps(self.attestation))
        slow["samples"][3]["lcp_ms"] = 1000
        slow["summary"]["maximum_lcp_ms"] = 1000.0
        slow = self._resign(slow)
        path = self._private_document("slow.json", slow)
        with self.assertRaisesRegex(
            acceptance.BrowserLcpAcceptanceError, "failed acceptance"
        ):
            self._verify(path)

    def test_stale_attestation_is_rejected(self) -> None:
        stale = json.loads(json.dumps(self.attestation))
        old = acceptance._now() - timedelta(hours=1)
        stale["issued_at"] = acceptance._format_time(old)
        stale["expires_at"] = acceptance._format_time(old + timedelta(seconds=300))
        stale = self._resign(stale)
        path = self._private_document("stale.json", stale)
        with self.assertRaisesRegex(
            acceptance.BrowserLcpAcceptanceError, "stale or temporally invalid"
        ):
            self._verify(path)

    def test_wrong_operation_and_live_release_are_rejected(self) -> None:
        with self.assertRaisesRegex(
            acceptance.BrowserLcpAcceptanceError, "another operation"
        ):
            self._verify(expected_operation_id=str(uuid.uuid4()))

        def wrong_health(_url: str, *, expected_release_digest: str):
            return self._health("f" * 64, generation=7)

        with self.assertRaisesRegex(
            acceptance.BrowserLcpAcceptanceError, "identity"
        ):
            self._verify(health_observer=wrong_health)

        def wrong_generation(_url: str, *, expected_release_digest: str):
            return self._health(expected_release_digest, generation=8)

        with self.assertRaisesRegex(
            acceptance.BrowserLcpAcceptanceError, "identity changed"
        ):
            self._verify(health_observer=wrong_generation)

    def test_fresh_tests_projection_does_not_satisfy_retained_gate(self) -> None:
        fresh = json.loads(json.dumps(self.attestation))
        fresh["samples"][1]["test_delivery_state"] = "fresh"
        fresh["samples"][1]["current_tests"] = False
        fresh = self._resign(fresh)
        path = self._private_document("fresh-tests.json", fresh)
        with self.assertRaisesRegex(
            acceptance.BrowserLcpAcceptanceError, "retained projection"
        ):
            self._verify(path)

    def test_runtime_drift_is_rejected(self) -> None:
        self.browser.chmod(0o755)
        self.browser.write_text("#!/bin/sh\nprintf '%s\\n' 'Chromium 1.2.3.4'\n")
        self.browser.chmod(0o555)
        with self.assertRaisesRegex(
            acceptance.BrowserLcpAcceptanceError, "runtime has drifted"
        ):
            self._verify()

    def test_producer_release_binding_cannot_be_substituted(self) -> None:
        changed = json.loads(json.dumps(self.attestation))
        changed["producer"]["browser_driver_sha256"] = "f" * 64
        changed = self._resign(changed)
        path = self._private_document("wrong-producer.json", changed)
        with self.assertRaisesRegex(
            acceptance.BrowserLcpAcceptanceError, "differs from the release"
        ):
            self._verify(path)

    def test_cookie_or_secret_fields_cannot_enter_evidence(self) -> None:
        changed = json.loads(json.dumps(self.attestation))
        changed["cookies"] = [{"name": "session", "value": "do-not-leak"}]
        # A caller holding the fixture key still cannot expand the schema.
        values = {
            key: value
            for key, value in changed.items()
            if key
            not in {
                "schema_version",
                "kind",
                "signing_key_id",
                "document_sha256",
                "signature_hmac_sha256",
            }
        }
        changed = acceptance._signed_attestation(values, signing_key=self.key)
        path = self._private_document("secret-field.json", changed)
        with self.assertRaisesRegex(
            acceptance.BrowserLcpAcceptanceError, "fields are invalid"
        ):
            self._verify(path)

    def test_consumption_is_atomic_and_replay_fails(self) -> None:
        output = self.private / "consumed.json"
        result = self._consume(output)
        self.assertEqual(result["kind"], acceptance.CONSUMPTION_KIND)
        self.assertEqual(self._validate_consumption(result), result)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        with self.assertRaises(acceptance.BrowserLcpReplayError):
            self._consume(output)

    def test_consumed_attestation_remains_verifiable_after_live_ttl(self) -> None:
        consumption = self._consume(self.private / "retained-consumption.json")
        consumed_at = acceptance._parse_time(
            consumption["consumed_at"], "consumption"
        )
        expired_at = acceptance._parse_time(
            self.attestation["expires_at"], "expiry"
        ) + timedelta(milliseconds=1)
        with self.assertRaisesRegex(
            acceptance.BrowserLcpAcceptanceError,
            "stale or temporally invalid",
        ):
            self._verify(now=expired_at)
        verified = acceptance.verify_historical_attestation_file(
            self.attestation_path,
            release=self.release,
            immutable_root=self.release.parent,
            runtime_lock_path=self.runtime_lock_path,
            signing_key_path=self.key_path,
            expected_operation_id=self.operation_id,
            verified_at=consumed_at,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )
        self.assertEqual(verified, self.attestation)

    def test_consumption_marker_requires_exact_fields(self) -> None:
        result = self._consume(self.private / "exact-consumption.json")
        unexpected = dict(result)
        unexpected["unexpected"] = True
        with self.assertRaisesRegex(
            acceptance.BrowserLcpAcceptanceError, "fields are invalid"
        ):
            self._validate_consumption(unexpected)

    def test_consumption_marker_rejects_wrong_bindings_and_time(self) -> None:
        result = self._consume(self.private / "binding-consumption.json")
        issued = acceptance._parse_time(self.attestation["issued_at"], "issue")
        expires = acceptance._parse_time(self.attestation["expires_at"], "expiry")
        cases = (
            (
                "attestation digest",
                self._reseal_consumption(
                    result, attestation_document_sha256="f" * 64
                ),
                acceptance._now(),
                "another attestation",
            ),
            (
                "malformed consumer UUID",
                self._reseal_consumption(result, consumer_operation_id="not-a-uuid"),
                acceptance._now(),
                "must be one UUID",
            ),
            (
                "other attestation UUID",
                self._reseal_consumption(
                    result, attestation_operation_id=str(uuid.uuid4())
                ),
                acceptance._now(),
                "operation binding",
            ),
            (
                "release digest",
                self._reseal_consumption(result, release_digest="f" * 64),
                acceptance._now(),
                "another release",
            ),
            (
                "consumed before issue",
                self._reseal_consumption(
                    result,
                    consumed_at=acceptance._format_time(
                        issued - timedelta(milliseconds=1)
                    ),
                ),
                issued,
                "temporally invalid",
            ),
            (
                "validated after expiry",
                result,
                expires + timedelta(milliseconds=1),
                "temporally invalid",
            ),
        )
        for label, document, observed_at, message in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    acceptance.BrowserLcpAcceptanceError, message
                ):
                    self._validate_consumption(document, now=observed_at)

    def test_private_publication_refuses_existing_or_nonprivate_parent(self) -> None:
        output = self.private / "once.json"
        acceptance._publish_private(output, {"ok": True}, uid=self.uid)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        with self.assertRaisesRegex(
            acceptance.BrowserLcpAcceptanceError, "already exists"
        ):
            acceptance._publish_private(output, {"ok": True}, uid=self.uid)
        public = self.root / "public"
        public.mkdir(mode=0o755)
        public.chmod(0o755)
        with self.assertRaisesRegex(
            acceptance.BrowserLcpAcceptanceError, "mode 0700"
        ):
            acceptance._publish_private(
                public / "evidence.json", {"ok": True}, uid=self.uid
            )

    def test_release_manifest_or_file_tamper_is_rejected(self) -> None:
        source = self.release / acceptance.RELEASE_BROWSER_DRIVER
        source.chmod(0o644)
        source.write_text("// changed\n", encoding="utf-8")
        source.chmod(0o444)
        with self.assertRaisesRegex(
            acceptance.BrowserLcpAcceptanceError, "failed verification"
        ):
            self._verify()

    def test_observation_rejects_duplicate_or_missing_viewport(self) -> None:
        duplicate = json.loads(json.dumps(self.observation))
        duplicate["samples"][2]["viewport"] = dict(
            acceptance.REQUIRED_VIEWPORTS[0]
        )
        with self.assertRaisesRegex(
            acceptance.BrowserLcpAcceptanceError, "failed acceptance"
        ):
            acceptance.verify_observation_document(
                duplicate,
                operation_id=self.operation_id,
                playwright_version="1.61.1",
                browser_product_version="142.0.7444.175",
                console_url=acceptance.DEFAULT_CONSOLE_URL,
                tests_url=acceptance.DEFAULT_TESTS_URL,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
