#!/usr/bin/env python3
"""Publish a retained, bounded inventory projection outside authority state."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import grp
import json
import os
from pathlib import Path
import signal
import stat
import sys
import threading
import time
from typing import Any
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/codex-dev-coordinator/scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from devcoordinator.inventory_projection import (  # noqa: E402
    InventoryProjectionError,
    empty_inventory,
    envelope,
    initialize_inventory_store,
    publish_retained_inventory,
    publish_projection,
    read_projection,
    verify_inventory_store,
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def api_json(
    base_url: str,
    endpoint: str,
    *,
    payload: dict[str, Any] | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urlrequest.Request(
        f"{base_url.rstrip('/')}{endpoint}",
        data=body,
        method="GET" if body is None else "POST",
        headers={
            "Host": "127.0.0.1",
            **({"Content-Type": "application/json"} if body is not None else {}),
        },
    )
    try:
        with urlrequest.urlopen(request, timeout=timeout) as response:
            raw = response.read(64 * 1024 * 1024 + 1)
    except (OSError, urlerror.URLError, urlerror.HTTPError) as error:
        raise InventoryProjectionError(f"observer API request failed: {error}") from error
    if len(raw) > 64 * 1024 * 1024:
        raise InventoryProjectionError("observer API reply exceeds its byte budget")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise InventoryProjectionError(f"observer API reply is invalid: {error}") from error
    if not isinstance(value, dict):
        raise InventoryProjectionError("observer API reply must be an object")
    return value


def projection_group(raw: str | None) -> int:
    if raw is None:
        return os.getegid()
    try:
        return int(grp.getgrnam(raw).gr_gid)
    except KeyError as error:
        raise InventoryProjectionError(f"projection group does not exist: {raw}") from error


def validate_runtime_config(args: argparse.Namespace) -> dict[str, Any]:
    project = Path(args.project)
    try:
        resolved = project.resolve(strict=True)
        metadata = project.lstat()
    except OSError as error:
        raise InventoryProjectionError("observer project root is unavailable") from error
    if (
        not project.is_absolute()
        or project != resolved
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or any(character in str(project) for character in "\0\r\n")
    ):
        raise InventoryProjectionError("observer project root must be a canonical directory")
    if not 2 <= args.interval_seconds <= 300:
        raise InventoryProjectionError("observer interval must be between 2 and 300 seconds")
    if not 0.1 <= args.request_timeout_seconds <= 300:
        raise InventoryProjectionError("observer request timeout must be between 0.1 and 300 seconds")
    if args.log_level not in {"debug", "info", "warn", "error"}:
        raise InventoryProjectionError("observer log level is invalid")
    parsed_url = urlparse(args.api_url)
    if (
        parsed_url.scheme not in {"http", "https"}
        or parsed_url.hostname not in {"127.0.0.1", "::1", "localhost"}
        or parsed_url.username is not None
        or parsed_url.password is not None
        or parsed_url.query
        or parsed_url.fragment
    ):
        raise InventoryProjectionError("observer API URL must be a local HTTP(S) URL")
    return {
        "ok": True,
        "project": str(project),
        "interval_seconds": args.interval_seconds,
        "request_timeout_seconds": args.request_timeout_seconds,
        "log_level": args.log_level,
    }


def initialize(args: argparse.Namespace) -> dict[str, Any]:
    target = args.publication.expanduser().absolute()
    database = args.database.expanduser().absolute()
    if target.exists() or target.is_symlink() or database.exists() or database.is_symlink():
        raise InventoryProjectionError("initial inventory store already exists")
    value = envelope(generation=1, inventory=empty_inventory(), published_at=utc_now())
    initialized = initialize_inventory_store(
        database,
        value,
        owner_uid=os.geteuid(),
        owner_gid=projection_group(args.publication_group),
    )
    try:
        publish_projection(
            target,
            value,
            owner_uid=os.geteuid(),
            owner_gid=projection_group(args.publication_group),
        )
    except BaseException:
        database.unlink(missing_ok=True)
        Path(f"{database}-wal").unlink(missing_ok=True)
        Path(f"{database}-shm").unlink(missing_ok=True)
        raise
    return {
        "ok": True,
        "initialized": True,
        "publication": str(target),
        "database": str(database),
        "generation": initialized["generation"],
    }


def verify(args: argparse.Namespace) -> dict[str, Any]:
    value = verify_inventory_store(
        args.database.expanduser().absolute(),
        args.publication.expanduser().absolute(),
        expected_owner_uid=os.geteuid(),
    )
    return {
        "ok": True,
        "publication": str(args.publication.expanduser().absolute()),
        "database": str(args.database.expanduser().absolute()),
        "generation": value["generation"],
        "retained_generations": value["retained_generations"],
        "read_only": True,
    }


def refresh_once(
    args: argparse.Namespace,
    current: dict[str, Any],
    *,
    group_id: int,
) -> dict[str, Any]:
    """Publish authority state immediately, then enrich it with host observation.

    Repository identity is cheap committed control-plane data.  It must not be
    held behind Docker sampling: a slow or failed observation may make runtime
    telemetry stale, but it must never leave Console inventory structurally
    empty.  Identical source reads are not republished.
    """

    reconciled = verify_inventory_store(
        args.database.expanduser().absolute(),
        args.publication.expanduser().absolute(),
        expected_owner_uid=os.geteuid(),
    )
    current = reconciled["envelope"]

    def publish_source(value: dict[str, Any]) -> dict[str, Any]:
        # This source call remains isolated in the bounded observer. Ordinary
        # Console reads never call it.
        inventory = api_json(
            args.api_url,
            "/v1/inventory/source",
            timeout=args.request_timeout_seconds,
        )
        if inventory == value.get("inventory"):
            return value
        next_value = envelope(
            generation=int(value["generation"]) + 1,
            inventory=inventory,
            published_at=utc_now(),
        )
        publish_retained_inventory(
            database=args.database.expanduser().absolute(),
            publication=args.publication.expanduser().absolute(),
            value=next_value,
            owner_uid=os.geteuid(),
            owner_gid=group_id,
        )
        return next_value

    current = publish_source(current)
    try:
        api_json(
            args.api_url,
            "/v1/observe",
            payload={"agent": "devcoordinator-observer", "project": args.project},
            timeout=args.request_timeout_seconds,
        )
    except Exception as error:
        print(
            json.dumps({
                "event": "inventory.observation_failed",
                "error": str(error)[:4096],
                "retained_generation": current["generation"],
            }, sort_keys=True),
            file=sys.stderr,
            flush=True,
        )
        return current
    return publish_source(current)


def serve(args: argparse.Namespace) -> dict[str, Any]:
    validate_runtime_config(args)
    publication = args.publication.expanduser().absolute()
    retained = verify_inventory_store(
        args.database.expanduser().absolute(),
        publication,
        expected_owner_uid=os.geteuid(),
    )
    current = retained["envelope"]
    group_id = projection_group(args.publication_group)
    stop = threading.Event()

    def request_stop(_signum: int, _frame: Any) -> None:
        stop.set()

    previous = {
        signum: signal.signal(signum, request_stop)
        for signum in (signal.SIGTERM, signal.SIGINT)
    }
    try:
        print(json.dumps({"status": "ready", "generation": current["generation"]}), flush=True)
        while not stop.is_set():
            started = time.monotonic()
            try:
                current = refresh_once(
                    args,
                    current,
                    group_id=group_id,
                )
            except Exception as error:
                print(
                    json.dumps({
                        "event": "inventory.refresh_failed",
                        "error": str(error)[:4096],
                        "retained_generation": current["generation"],
                    }, sort_keys=True),
                    file=sys.stderr,
                    flush=True,
                )
            remaining = max(0.0, args.interval_seconds - (time.monotonic() - started))
            stop.wait(remaining)
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    return {"ok": True, "stopped": True, "generation": current["generation"]}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    actions = result.add_subparsers(dest="action", required=True)
    for name in ("init", "verify", "config-check", "serve"):
        command = actions.add_parser(name)
        if name != "config-check":
            command.add_argument("--publication", type=Path, required=True)
            command.add_argument("--database", type=Path, required=True)
        if name in {"init", "serve"}:
            command.add_argument("--publication-group")
        if name in {"config-check", "serve"}:
            command.add_argument("--api-url", default="http://127.0.0.1:29876")
            command.add_argument("--project", required=True)
            command.add_argument("--interval-seconds", type=float, default=10.0)
            command.add_argument("--request-timeout-seconds", type=float, default=10.0)
            command.add_argument("--log-level", default="info")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.action == "init":
            result = initialize(args)
        elif args.action == "verify":
            result = verify(args)
        elif args.action == "config-check":
            result = validate_runtime_config(args)
        else:
            result = serve(args)
    except (OSError, ValueError, InventoryProjectionError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
