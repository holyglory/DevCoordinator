#!/usr/bin/env python3
"""Render non-secret background config and fence Telegram state handoff.

The renderer publishes a private, manifest-committed transaction directory.
It deliberately copies no Console/OIDC/session credentials.  Telegram state
copy is a separate, explicit first-adoption step which requires recent
root-private evidence that the legacy writer is stopped; neither service
startup nor release installation invokes it implicitly.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Any, Mapping
import uuid


TRANSACTION_KIND = "devcoordinator-background-config-transaction"
FENCE_KIND = "devcoordinator-notification-writer-fence"
CONTRACT_VERSION = 1
MAX_ENV_BYTES = 1024 * 1024
MAX_STATE_BYTES = 16 * 1024 * 1024
MAX_ATTESTATION_BYTES = 64 * 1024
LOG_LEVELS = frozenset({"debug", "info", "warn", "error"})
EMAIL_RE = re.compile(
    r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+"
)
ENV_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
SAFE_ENV_VALUE_RE = re.compile(r"[A-Za-z0-9_./,@:+-]{1,16384}")
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")


class HandoffError(RuntimeError):
    pass


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _timestamp(value: datetime | None = None) -> str:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise HandoffError("timestamp must include a timezone")
    return current.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise HandoffError(f"{field} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise HandoffError(f"{field} is invalid") from error
    if parsed.tzinfo is None:
        raise HandoffError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _absolute(value: str) -> Path:
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    return candidate


def _bounded_float(value: str) -> float:
    try:
        result = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("timing value must be numeric") from error
    if not 0.1 <= result <= 300:
        raise argparse.ArgumentTypeError("timing value must be between 0.1 and 300")
    return result


def _uid(value: str) -> int:
    try:
        result = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("UID/GID must be numeric") from error
    if result < 0:
        raise argparse.ArgumentTypeError("UID/GID cannot be negative")
    return result


def _safe_read(
    path: Path,
    *,
    maximum_bytes: int,
    owners: set[int],
    require_private: bool = False,
) -> tuple[bytes, os.stat_result]:
    if not path.is_absolute():
        raise HandoffError("input path must be absolute")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in owners
            or before.st_size < 1
            or before.st_size > maximum_bytes
            or stat.S_IMODE(before.st_mode) & (0o077 if require_private else 0o022)
        ):
            raise HandoffError(f"input file is unsafe: {path}")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(remaining, 1024 * 1024))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        after = os.fstat(descriptor)
        if (
            remaining
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise HandoffError(f"input file changed while reading: {path}")
        return b"".join(chunks), before
    finally:
        os.close(descriptor)


def _parse_env(raw: bytes) -> dict[str, str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise HandoffError("legacy Console environment is not UTF-8") from error
    result: dict[str, str] = {}
    for number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(
            r"(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)", line
        )
        if match is None:
            raise HandoffError(f"legacy Console environment line {number} is invalid")
        key, value = match.groups()
        if key in result:
            raise HandoffError(f"legacy Console environment repeats {key}")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if any(character in value for character in "\0\r\n"):
            raise HandoffError(f"legacy Console environment {key} is invalid")
        result[key] = value
    return result


def _canonical_project_root(path: Path) -> str:
    if not path.is_absolute() or any(character in str(path) for character in "\0\r\n"):
        raise HandoffError("background project root must be an absolute path")
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as error:
        raise HandoffError("background project root is unavailable") from error
    if resolved != path or not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise HandoffError("background project root must be a canonical directory")
    value = str(resolved)
    if SAFE_ENV_VALUE_RE.fullmatch(value) is None:
        raise HandoffError("background project root cannot be represented safely")
    return value


def _canonical_emails(raw: str) -> str:
    values = sorted(
        {
            value.strip().lower()
            for value in raw.split(",")
            if value.strip()
        }
    )
    if not values or len(values) > 1000:
        raise HandoffError("ALLOWED_EMAILS must contain at least one administrator")
    if any(len(value) > 320 or EMAIL_RE.fullmatch(value) is None for value in values):
        raise HandoffError("ALLOWED_EMAILS contains an invalid administrator email")
    canonical = ",".join(values)
    if SAFE_ENV_VALUE_RE.fullmatch(canonical) is None:
        raise HandoffError("administrator email list cannot be represented safely")
    return canonical


def _render_env(values: Mapping[str, str]) -> bytes:
    if any(ENV_KEY_RE.fullmatch(key) is None for key in values):
        raise HandoffError("background environment key is invalid")
    if any(SAFE_ENV_VALUE_RE.fullmatch(value) is None for value in values.values()):
        raise HandoffError("background environment value is invalid")
    return "".join(f"{key}={values[key]}\n" for key in sorted(values)).encode("utf-8")


def _write_descriptor(descriptor: int, value: bytes) -> None:
    offset = 0
    while offset < len(value):
        written = os.write(descriptor, value[offset:])
        if written <= 0:
            raise HandoffError("background configuration write was incomplete")
        offset += written
    os.fsync(descriptor)


def _write_new_file(
    path: Path,
    value: bytes,
    *,
    owner_uid: int,
    owner_gid: int,
    mode: int,
) -> None:
    parent = path.parent
    parent_info = parent.lstat()
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or stat.S_ISLNK(parent_info.st_mode)
        or parent_info.st_uid not in {0, os.geteuid(), owner_uid}
        or stat.S_IMODE(parent_info.st_mode) & 0o022
    ):
        raise HandoffError(f"output parent is unsafe: {parent}")
    if path.exists() or path.is_symlink():
        raise HandoffError(f"output already exists: {path}")
    temporary = parent / f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.partial"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, owner_uid, owner_gid)
        _write_descriptor(descriptor, value)
    finally:
        os.close(descriptor)
    try:
        os.link(temporary, path, follow_symlinks=False)
        temporary.unlink()
        directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _validate_config_values(
    notifications: Mapping[str, str], observer: Mapping[str, str]
) -> None:
    if set(notifications) != {
        "DEVCOORDINATOR_NOTIFICATION_ADMIN_EMAILS",
        "DEVCOORDINATOR_NOTIFICATION_PROJECT",
        "LOG_LEVEL",
    }:
        raise HandoffError("notification configuration fields are invalid")
    if set(observer) != {
        "DEVCOORDINATOR_OBSERVER_INTERVAL_SECONDS",
        "DEVCOORDINATOR_OBSERVER_PROJECT",
        "DEVCOORDINATOR_OBSERVER_REQUEST_TIMEOUT_SECONDS",
        "LOG_LEVEL",
    }:
        raise HandoffError("observer configuration fields are invalid")
    if notifications["DEVCOORDINATOR_NOTIFICATION_PROJECT"] != observer["DEVCOORDINATOR_OBSERVER_PROJECT"]:
        raise HandoffError("background project roots are contradictory")
    _canonical_emails(notifications["DEVCOORDINATOR_NOTIFICATION_ADMIN_EMAILS"])
    if notifications["LOG_LEVEL"] not in LOG_LEVELS or observer["LOG_LEVEL"] not in LOG_LEVELS:
        raise HandoffError("background LOG_LEVEL is invalid")
    for field in (
        "DEVCOORDINATOR_OBSERVER_INTERVAL_SECONDS",
        "DEVCOORDINATOR_OBSERVER_REQUEST_TIMEOUT_SECONDS",
    ):
        value = float(observer[field])
        if not 0.1 <= value <= 300:
            raise HandoffError("observer timing configuration is invalid")
    if float(observer["DEVCOORDINATOR_OBSERVER_INTERVAL_SECONDS"]) < 2:
        raise HandoffError("observer interval must be at least two seconds")


def _parse_rendered_env(raw: bytes) -> dict[str, str]:
    result = _parse_env(raw)
    if any(SAFE_ENV_VALUE_RE.fullmatch(value) is None for value in result.values()):
        raise HandoffError("rendered background environment contains an unsafe value")
    return result


def render_transaction(args: argparse.Namespace) -> dict[str, Any]:
    source, _metadata = _safe_read(
        args.legacy_console_env,
        maximum_bytes=MAX_ENV_BYTES,
        owners={args.source_owner_uid},
    )
    legacy = _parse_env(source)
    project = _canonical_project_root(args.project_root)
    emails = _canonical_emails(legacy.get("ALLOWED_EMAILS", ""))
    log_level = args.log_level.lower()
    if log_level not in LOG_LEVELS:
        raise HandoffError("LOG_LEVEL must be one of debug|info|warn|error")
    notifications = {
        "DEVCOORDINATOR_NOTIFICATION_ADMIN_EMAILS": emails,
        "DEVCOORDINATOR_NOTIFICATION_PROJECT": project,
        "LOG_LEVEL": log_level,
    }
    observer = {
        "DEVCOORDINATOR_OBSERVER_INTERVAL_SECONDS": str(args.observer_interval_seconds),
        "DEVCOORDINATOR_OBSERVER_PROJECT": project,
        "DEVCOORDINATOR_OBSERVER_REQUEST_TIMEOUT_SECONDS": str(
            args.observer_request_timeout_seconds
        ),
        "LOG_LEVEL": log_level,
    }
    _validate_config_values(notifications, observer)
    notification_body = _render_env(notifications)
    observer_body = _render_env(observer)
    output = args.output_directory
    if output.exists() or output.is_symlink():
        raise HandoffError("background config transaction already exists")
    parent = output.parent
    parent_info = parent.lstat()
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or stat.S_ISLNK(parent_info.st_mode)
        or parent_info.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(parent_info.st_mode) & 0o022
    ):
        raise HandoffError("background config transaction parent is unsafe")
    output.mkdir(mode=0o700)
    try:
        _write_new_file(
            output / "notifications.env",
            notification_body,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
            mode=0o400,
        )
        _write_new_file(
            output / "observer.env",
            observer_body,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
            mode=0o400,
        )
        created = _timestamp()
        manifest = {
            "schema_version": CONTRACT_VERSION,
            "kind": TRANSACTION_KIND,
            "created_at": created,
            "project_root": project,
            "legacy_console_env_sha256": _sha256(source),
            "files": {
                "notifications.env": _sha256(notification_body),
                "observer.env": _sha256(observer_body),
            },
        }
        manifest_body = (
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        # The manifest is the transaction commit marker and is always last.
        _write_new_file(
            output / "transaction.json",
            manifest_body,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
            mode=0o400,
        )
        directory = os.open(output, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        for child in output.iterdir():
            child.unlink()
        output.rmdir()
        raise
    return verify_transaction(output)


def verify_transaction(directory: Path) -> dict[str, Any]:
    info = directory.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise HandoffError("background config transaction directory is unsafe")
    if {entry.name for entry in directory.iterdir()} != {
        "notifications.env",
        "observer.env",
        "transaction.json",
    }:
        raise HandoffError("background config transaction contents are invalid")
    notification_body, _ = _safe_read(
        directory / "notifications.env",
        maximum_bytes=MAX_ENV_BYTES,
        owners={0, os.geteuid()},
        require_private=True,
    )
    observer_body, _ = _safe_read(
        directory / "observer.env",
        maximum_bytes=MAX_ENV_BYTES,
        owners={0, os.geteuid()},
        require_private=True,
    )
    manifest_body, _ = _safe_read(
        directory / "transaction.json",
        maximum_bytes=MAX_ENV_BYTES,
        owners={0, os.geteuid()},
        require_private=True,
    )
    try:
        manifest = json.loads(manifest_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HandoffError("background config transaction manifest is invalid") from error
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version",
        "kind",
        "created_at",
        "project_root",
        "legacy_console_env_sha256",
        "files",
    }:
        raise HandoffError("background config transaction manifest fields are invalid")
    if manifest["schema_version"] != CONTRACT_VERSION or manifest["kind"] != TRANSACTION_KIND:
        raise HandoffError("background config transaction discriminator is unsupported")
    _parse_timestamp(manifest["created_at"], "created_at")
    if SHA256_RE.fullmatch(str(manifest["legacy_console_env_sha256"])) is None:
        raise HandoffError("legacy Console environment fingerprint is invalid")
    if manifest["files"] != {
        "notifications.env": _sha256(notification_body),
        "observer.env": _sha256(observer_body),
    }:
        raise HandoffError("background config transaction file fingerprints changed")
    notifications = _parse_rendered_env(notification_body)
    observer = _parse_rendered_env(observer_body)
    _validate_config_values(notifications, observer)
    if notifications["DEVCOORDINATOR_NOTIFICATION_PROJECT"] != manifest["project_root"]:
        raise HandoffError("background config transaction project root changed")
    return {
        "ok": True,
        "kind": TRANSACTION_KIND,
        "directory": str(directory),
        "project_root": manifest["project_root"],
        "files": manifest["files"],
        "administrator_count": len(
            notifications["DEVCOORDINATOR_NOTIFICATION_ADMIN_EMAILS"].split(",")
        ),
    }


def _fence(
    path: Path,
    *,
    source_path: Path,
    source_sha256: str,
    legacy_unit: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    raw, _ = _safe_read(
        path,
        maximum_bytes=MAX_ATTESTATION_BYTES,
        owners={0},
        require_private=True,
    )
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HandoffError("notification writer fence is invalid JSON") from error
    fields = {
        "schema_version",
        "kind",
        "deployment_id",
        "captured_at",
        "legacy_writer_unit",
        "legacy_writer_inactive",
        "source_path",
        "source_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise HandoffError("notification writer fence fields are invalid")
    if value["schema_version"] != CONTRACT_VERSION or value["kind"] != FENCE_KIND:
        raise HandoffError("notification writer fence discriminator is unsupported")
    try:
        if str(uuid.UUID(value["deployment_id"])) != value["deployment_id"]:
            raise ValueError
    except (ValueError, AttributeError, TypeError) as error:
        raise HandoffError("notification writer fence deployment ID is invalid") from error
    captured = _parse_timestamp(value["captured_at"], "captured_at")
    current = now or datetime.now(timezone.utc)
    if captured > current + timedelta(seconds=5) or current - captured > timedelta(minutes=5):
        raise HandoffError("notification writer fence is stale")
    if (
        value["legacy_writer_unit"] != legacy_unit
        or value["legacy_writer_inactive"] is not True
        or value["source_path"] != str(source_path)
        or value["source_sha256"] != source_sha256
    ):
        raise HandoffError("notification writer fence contradicts the state handoff")
    return value


def copy_telegram_state(args: argparse.Namespace) -> dict[str, Any]:
    source, _ = _safe_read(
        args.source,
        maximum_bytes=MAX_STATE_BYTES,
        owners={args.source_owner_uid},
        require_private=True,
    )
    digest = _sha256(source)
    if digest != args.expected_source_sha256:
        raise HandoffError("Telegram source state fingerprint changed")
    fence = _fence(
        args.fence_attestation,
        source_path=args.source,
        source_sha256=digest,
        legacy_unit=args.legacy_writer_unit,
    )
    def existing_copy(
        path: Path, *, owner_uid: int, owner_gid: int, mode: int
    ) -> bool:
        try:
            path.lstat()
        except FileNotFoundError:
            return False
        payload, metadata = _safe_read(
            path,
            maximum_bytes=MAX_STATE_BYTES,
            owners={owner_uid},
            require_private=True,
        )
        if (
            payload != source
            or metadata.st_uid != owner_uid
            or metadata.st_gid != owner_gid
            or stat.S_IMODE(metadata.st_mode) != mode
        ):
            raise HandoffError(
                f"existing Telegram handoff copy is contradictory: {path}"
            )
        return True

    rollback_exists = existing_copy(
        args.rollback, owner_uid=0, owner_gid=0, mode=0o400
    )
    destination_exists = existing_copy(
        args.destination,
        owner_uid=args.destination_owner_uid,
        owner_gid=args.destination_owner_gid,
        mode=0o600,
    )
    if destination_exists and not rollback_exists:
        raise HandoffError(
            "Telegram destination exists without its root-private rollback copy"
        )
    # Rollback evidence is published first.  The legacy source remains intact;
    # this extra root-private copy binds the exact cutover bytes.
    if not rollback_exists:
        _write_new_file(
            args.rollback,
            source,
            owner_uid=0,
            owner_gid=0,
            mode=0o400,
        )
    if not destination_exists:
        _write_new_file(
            args.destination,
            source,
            owner_uid=args.destination_owner_uid,
            owner_gid=args.destination_owner_gid,
            mode=0o600,
        )
    return {
        "ok": True,
        "kind": "devcoordinator-notification-state-handoff",
        "deployment_id": fence["deployment_id"],
        "source_sha256": digest,
        "destination": str(args.destination),
        "rollback": str(args.rollback),
        "legacy_writer_fenced": True,
    }


def verify_state(args: argparse.Namespace) -> dict[str, Any]:
    raw, _ = _safe_read(
        args.state,
        maximum_bytes=MAX_STATE_BYTES,
        owners={args.expected_owner_uid},
        require_private=True,
    )
    digest = _sha256(raw)
    if args.expected_sha256 and digest != args.expected_sha256:
        raise HandoffError("Telegram state fingerprint changed")
    # Structural parsing happens again under the destination UID in the
    # notification worker's mandatory --check preflight.
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HandoffError("Telegram state is not valid JSON") from error
    if not isinstance(value, dict):
        raise HandoffError("Telegram state must be a JSON object")
    return {
        "ok": True,
        "kind": "devcoordinator-notification-state-verification",
        "state": str(args.state),
        "sha256": digest,
        "owner_uid": args.expected_owner_uid,
        "destination_parser_preflight_required": True,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    render = commands.add_parser("render")
    render.add_argument("--legacy-console-env", type=_absolute, required=True)
    render.add_argument("--source-owner-uid", type=_uid, required=True)
    render.add_argument("--project-root", type=_absolute, required=True)
    render.add_argument("--output-directory", type=_absolute, required=True)
    render.add_argument("--observer-interval-seconds", type=_bounded_float, default=10.0)
    # A full host observation may inspect hundreds of containers.  Retained
    # inventory is published before that work, so let sampling complete in the
    # background instead of forcing a permanent ten-second timeout loop.
    render.add_argument("--observer-request-timeout-seconds", type=_bounded_float, default=300.0)
    render.add_argument("--log-level", default="info")
    verify = commands.add_parser("verify-config")
    verify.add_argument("--directory", type=_absolute, required=True)
    copy = commands.add_parser("copy-telegram-state")
    copy.add_argument("--source", type=_absolute, required=True)
    copy.add_argument("--destination", type=_absolute, required=True)
    copy.add_argument("--rollback", type=_absolute, required=True)
    copy.add_argument("--fence-attestation", type=_absolute, required=True)
    copy.add_argument("--legacy-writer-unit", required=True)
    copy.add_argument("--expected-source-sha256", required=True)
    copy.add_argument("--source-owner-uid", type=_uid, required=True)
    copy.add_argument("--destination-owner-uid", type=_uid, required=True)
    copy.add_argument("--destination-owner-gid", type=_uid, required=True)
    state = commands.add_parser("verify-state")
    state.add_argument("--state", type=_absolute, required=True)
    state.add_argument("--expected-owner-uid", type=_uid, required=True)
    state.add_argument("--expected-sha256")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "render":
            value = render_transaction(args)
        elif args.command == "verify-config":
            value = verify_transaction(args.directory)
        elif args.command == "copy-telegram-state":
            value = copy_telegram_state(args)
        else:
            value = verify_state(args)
    except (HandoffError, OSError, ValueError) as error:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error_code": "background_service_handoff_failed",
                    "error": str(error),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
