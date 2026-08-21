from __future__ import annotations

import os
import unittest
from unittest import mock

import dev_coordinator


class UniversalTestReadAuthorityTests(unittest.TestCase):
    def test_server_wide_default_and_activation_flag_are_testd_only(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch.object(
                dev_coordinator, "authority_mode", return_value="system"
            ):
                self.assertEqual(dev_coordinator._test_read_authority(), "testd")
        with mock.patch.dict(
            os.environ,
            {dev_coordinator.TEST_READ_AUTHORITY_ENV: "testd"},
            clear=True,
        ):
            with mock.patch.object(
                dev_coordinator, "authority_mode", return_value="system"
            ):
                self.assertEqual(dev_coordinator._test_read_authority(), "testd")

    def test_legacy_reads_are_confined_to_explicit_account_mode(self) -> None:
        with mock.patch.dict(
            os.environ,
            {dev_coordinator.TEST_READ_AUTHORITY_ENV: "legacy"},
            clear=True,
        ):
            with mock.patch.object(
                dev_coordinator, "authority_mode", return_value="account"
            ):
                self.assertEqual(dev_coordinator._test_read_authority(), "legacy")
            for mode in ("system", "service"):
                with self.subTest(mode=mode), mock.patch.object(
                    dev_coordinator, "authority_mode", return_value=mode
                ):
                    with self.assertRaisesRegex(RuntimeError, "forbidden"):
                        dev_coordinator._test_read_authority()

    def test_activated_testd_never_falls_back_to_legacy_authority_reads(self) -> None:
        with (
            mock.patch.dict(
                os.environ,
                {dev_coordinator.TEST_READ_AUTHORITY_ENV: "testd"},
                clear=True,
            ),
            mock.patch.object(
                dev_coordinator, "authority_mode", return_value="system"
            ),
            mock.patch.object(
                dev_coordinator, "configured_broker_profile", return_value=None
            ),
            mock.patch.object(
                dev_coordinator,
                "CoordinatorTestRecords",
                side_effect=AssertionError("legacy authority read was opened"),
            ),
            mock.patch.object(
                dev_coordinator.AccountStore,
                "open_default_read_only",
                side_effect=AssertionError("legacy authority catalog was opened"),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "legacy authority statistics"):
                dev_coordinator.coordinated_test_statistics_read(
                    project="repo-tests", days=30, limit=25
                )
            with self.assertRaisesRegex(RuntimeError, "legacy authority fleet"):
                dev_coordinator.coordinated_test_fleet_read(hours=24)
            with self.assertRaisesRegex(RuntimeError, "legacy repository catalog"):
                dev_coordinator.coordinated_test_repository_list()

    def test_invalid_read_authority_fails_before_any_data_source_is_opened(self) -> None:
        with mock.patch.dict(
            os.environ,
            {dev_coordinator.TEST_READ_AUTHORITY_ENV: "both"},
            clear=True,
        ):
            with mock.patch.object(
                dev_coordinator, "authority_mode", return_value="system"
            ):
                with self.assertRaisesRegex(ValueError, "must be 'testd' or 'legacy'"):
                    dev_coordinator._test_read_authority()


if __name__ == "__main__":
    unittest.main()
