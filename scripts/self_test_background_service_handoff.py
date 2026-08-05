#!/usr/bin/env python3
"""Focused fail-closed tests for background config and notification handoff."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
from unittest import mock
import uuid


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import prepare_background_service_handoff as handoff  # noqa: E402
import devcoordinator_observer as observer  # noqa: E402


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary).resolve()
        root.chmod(0o700)
        project = root / "project"
        project.mkdir(mode=0o700)
        legacy = root / "console.env"
        legacy.write_text(
            "\n".join(
                (
                    "ALLOWED_EMAILS=Second.User+ops@example.test,owner@example.test,OWNER@example.test",
                    "SESSION_SECRET=fixture-session-secret",
                    "GOOGLE_CLIENT_SECRET=fixture-google-secret",
                    "UPSTREAM_AUTH_PASSWORD=fixture-upstream-password",
                    "",
                )
            ),
            encoding="utf-8",
        )
        legacy.chmod(0o600)
        output = root / "transaction"
        args = SimpleNamespace(
            legacy_console_env=legacy,
            source_owner_uid=os.geteuid(),
            project_root=project,
            output_directory=output,
            observer_interval_seconds=7.5,
            observer_request_timeout_seconds=4.0,
            log_level="warn",
        )
        rendered = handoff.render_transaction(args)
        expect(rendered["administrator_count"] == 2, "admin emails were not canonicalized")
        verified = handoff.verify_transaction(output)
        expect(verified == rendered, "config transaction verification changed metadata")
        combined = (output / "notifications.env").read_bytes() + (output / "observer.env").read_bytes()
        expect(
            b"SECRET_CANARY" not in combined
            and b"SESSION_SECRET" not in combined
            and b"GOOGLE_CLIENT_SECRET" not in combined
            and b"UPSTREAM_AUTH" not in combined,
            "background config transaction copied Console/OIDC/route credentials",
        )
        notification_config = handoff._parse_rendered_env(
            (output / "notifications.env").read_bytes()
        )
        expect(
            notification_config["DEVCOORDINATOR_NOTIFICATION_ADMIN_EMAILS"]
            == "owner@example.test,second.user+ops@example.test",
            "notification owners are not canonical",
        )
        observer_config = handoff._parse_rendered_env(
            (output / "observer.env").read_bytes()
        )
        checked = observer.validate_runtime_config(
            SimpleNamespace(
                project=observer_config["DEVCOORDINATOR_OBSERVER_PROJECT"],
                interval_seconds=float(
                    observer_config["DEVCOORDINATOR_OBSERVER_INTERVAL_SECONDS"]
                ),
                request_timeout_seconds=float(
                    observer_config[
                        "DEVCOORDINATOR_OBSERVER_REQUEST_TIMEOUT_SECONDS"
                    ]
                ),
                api_url="http://127.0.0.1:29876",
                log_level=observer_config["LOG_LEVEL"],
            )
        )
        expect(checked["ok"] is True, "observer parser rejected rendered config")
        defaults = handoff.parser().parse_args([
            "render",
            "--legacy-console-env", str(legacy),
            "--source-owner-uid", str(os.geteuid()),
            "--project-root", str(project),
            "--output-directory", str(root / "defaults"),
        ])
        expect(
            defaults.observer_request_timeout_seconds == 300.0,
            "observer default timeout cannot cover a bounded full-host sample",
        )

        try:
            handoff.render_transaction(args)
        except handoff.HandoffError:
            pass
        else:
            raise AssertionError("config transaction overwrote an existing publication")

        observer_file = output / "observer.env"
        observer_file.chmod(0o600)
        observer_file.write_text(
            observer_file.read_text(encoding="utf-8").replace("7.5", "0.1"),
            encoding="utf-8",
        )
        observer_file.chmod(0o400)
        try:
            handoff.verify_transaction(output)
        except handoff.HandoffError:
            pass
        else:
            raise AssertionError("tampered config transaction passed verification")

        unsafe_link = root / "console-link.env"
        unsafe_link.symlink_to(legacy)
        link_args = SimpleNamespace(**vars(args))
        link_args.legacy_console_env = unsafe_link
        link_args.output_directory = root / "link-transaction"
        try:
            handoff.render_transaction(link_args)
        except (OSError, handoff.HandoffError):
            pass
        else:
            raise AssertionError("config renderer followed a legacy env symlink")

        state = b'{"version":1,"bots":[],"requests":[],"eventCursor":null}\n'
        digest = "sha256:" + hashlib.sha256(state).hexdigest()
        deployment_id = str(uuid.UUID("11111111-2222-4333-8444-555555555555"))
        now = datetime.now(timezone.utc)
        fence_value = {
            "schema_version": 1,
            "kind": handoff.FENCE_KIND,
            "deployment_id": deployment_id,
            "captured_at": handoff._timestamp(now),
            "legacy_writer_unit": "devops-console.service",
            "legacy_writer_inactive": True,
            "source_path": "/var/lib/devops-console/telegram-control.json",
            "source_sha256": digest,
        }
        fence_raw = json.dumps(fence_value).encode("utf-8")
        with mock.patch.object(handoff, "_safe_read", return_value=(fence_raw, None)):
            fence = handoff._fence(
                Path("/private/fence.json"),
                source_path=Path(fence_value["source_path"]),
                source_sha256=digest,
                legacy_unit="devops-console.service",
                now=now,
            )
        expect(fence["deployment_id"] == deployment_id, "valid writer fence was rejected")
        stale = dict(fence_value)
        stale["captured_at"] = handoff._timestamp(now - timedelta(minutes=6))
        with mock.patch.object(
            handoff,
            "_safe_read",
            return_value=(json.dumps(stale).encode("utf-8"), None),
        ):
            try:
                handoff._fence(
                    Path("/private/fence.json"),
                    source_path=Path(fence_value["source_path"]),
                    source_sha256=digest,
                    legacy_unit="devops-console.service",
                    now=now,
                )
            except handoff.HandoffError:
                pass
            else:
                raise AssertionError("stale writer fence authorized state handoff")

        writes: list[tuple[Path, bytes, int, int, int]] = []
        copy_root = root / "telegram-copy"
        copy_root.mkdir(mode=0o700)
        copy_args = SimpleNamespace(
            source=Path(fence_value["source_path"]),
            destination=copy_root / "destination.json",
            rollback=copy_root / "rollback.json",
            fence_attestation=Path("/private/fence.json"),
            legacy_writer_unit="devops-console.service",
            expected_source_sha256=digest,
            source_owner_uid=1001,
            destination_owner_uid=992,
            destination_owner_gid=992,
        )

        def record_write(
            path: Path,
            value: bytes,
            *,
            owner_uid: int,
            owner_gid: int,
            mode: int,
        ) -> None:
            writes.append((path, value, owner_uid, owner_gid, mode))

        with (
            mock.patch.object(handoff, "_safe_read", return_value=(state, None)),
            mock.patch.object(handoff, "_fence", return_value=fence_value),
            mock.patch.object(handoff, "_write_new_file", side_effect=record_write),
        ):
            copied = handoff.copy_telegram_state(copy_args)
        expect(
            copied["legacy_writer_fenced"] is True
            and writes
            == [
                (copy_args.rollback, state, 0, 0, 0o400),
                (copy_args.destination, state, 992, 992, 0o600),
            ],
            "Telegram state handoff omitted rollback or destination ownership",
        )
        wrong = SimpleNamespace(**vars(copy_args))
        wrong.expected_source_sha256 = "sha256:" + "0" * 64
        with (
            mock.patch.object(handoff, "_safe_read", return_value=(state, None)),
            mock.patch.object(handoff, "_fence") as fence_call,
        ):
            try:
                handoff.copy_telegram_state(wrong)
            except handoff.HandoffError:
                pass
            else:
                raise AssertionError("changed Telegram state was copied")
            fence_call.assert_not_called()

        resume_root = root / "telegram-resume"
        resume_root.mkdir(mode=0o700)
        resume_source = resume_root / "legacy.json"
        resume_source.write_bytes(state)
        resume_source.chmod(0o600)
        resume_rollback = resume_root / "rollback.json"
        resume_destination = resume_root / "destination.json"
        resume_fence = resume_root / "fence.json"
        resume_operation = str(uuid.uuid4())
        resume_fence.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": handoff.FENCE_KIND,
                    "deployment_id": resume_operation,
                    "captured_at": handoff._timestamp(),
                    "legacy_writer_unit": "devops-console.service",
                    "legacy_writer_inactive": True,
                    "source_path": str(resume_source),
                    "source_sha256": digest,
                }
            ),
            encoding="utf-8",
        )
        resume_fence.chmod(0o600)
        resume_args = SimpleNamespace(
            source=resume_source,
            destination=resume_destination,
            rollback=resume_rollback,
            fence_attestation=resume_fence,
            legacy_writer_unit="devops-console.service",
            expected_source_sha256=digest,
            source_owner_uid=os.geteuid(),
            destination_owner_uid=os.geteuid(),
            destination_owner_gid=os.getegid(),
        )
        resume_fence_value = json.loads(resume_fence.read_text(encoding="utf-8"))
        copies: dict[Path, tuple[bytes, int, int, int]] = {}

        def state_read(path, **_kwargs):
            if path == resume_source:
                return state, SimpleNamespace(
                    st_uid=os.geteuid(),
                    st_gid=os.getegid(),
                    st_mode=stat.S_IFREG | 0o600,
                )
            value, owner_uid, owner_gid, mode = copies[path]
            return value, SimpleNamespace(
                st_uid=owner_uid,
                st_gid=owner_gid,
                st_mode=stat.S_IFREG | mode,
            )

        def state_write(path, value, *, owner_uid, owner_gid, mode):
            path.write_bytes(value)
            path.chmod(mode)
            copies[path] = (value, owner_uid, owner_gid, mode)

        with (
            mock.patch.object(handoff, "_safe_read", side_effect=state_read),
            mock.patch.object(handoff, "_fence", return_value=resume_fence_value),
            mock.patch.object(handoff, "_write_new_file", side_effect=state_write),
        ):
            first_copy = handoff.copy_telegram_state(resume_args)
            second_copy = handoff.copy_telegram_state(resume_args)
        expect(first_copy == second_copy, "exact Telegram handoff did not resume")
        resume_destination.unlink()
        copies.pop(resume_destination)
        with (
            mock.patch.object(handoff, "_safe_read", side_effect=state_read),
            mock.patch.object(handoff, "_fence", return_value=resume_fence_value),
            mock.patch.object(handoff, "_write_new_file", side_effect=state_write),
        ):
            recovered_copy = handoff.copy_telegram_state(resume_args)
        expect(
            recovered_copy == first_copy
            and resume_destination.read_bytes() == state
            and resume_rollback.read_bytes() == state,
            "Telegram handoff did not recover after the rollback-copy phase",
        )

    print("background service handoff self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
