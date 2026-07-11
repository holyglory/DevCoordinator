#!/usr/bin/env python3
"""Prove the production coordinator anonymous/authenticated HTTP boundary."""

from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import sys
import time
from pathlib import Path
from typing import Callable

from secure_cutover_io import SecureIOError, open_private_parent, read_private_regular


class AuthBoundaryError(RuntimeError):
    pass


INVENTORY_MAX_BYTES = 16 * 1024 * 1024
TRANSIENT_TRANSPORT_ERRORS = (
    ConnectionRefusedError,
    ConnectionResetError,
    ConnectionAbortedError,
    TimeoutError,
    socket.timeout,
    http.client.RemoteDisconnected,
)


def caused_by_missing_file(error: BaseException) -> bool:
    """Return true only when a wrapped secure read failed with ENOENT."""

    current: BaseException | None = error
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        if isinstance(current, FileNotFoundError):
            return True
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return False


def read_token(token_file: Path) -> str:
    try:
        token = read_private_regular(token_file, label="coordinator token").decode("utf-8").strip()
    except (SecureIOError, UnicodeDecodeError) as error:
        raise AuthBoundaryError(str(error)) from error
    if not token or len(token.encode("utf-8")) > 4096:
        raise AuthBoundaryError("coordinator token is empty or oversized")
    return token


def http_status(host: str, port: int, timeout: float, path: str, bearer: str | None) -> int:
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    headers = {"Authorization": f"Bearer {bearer}"} if bearer else {}
    try:
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def check_boundary(
    *,
    token_file: Path,
    host: str = "127.0.0.1",
    port: int = 29876,
    timeout: float = 60.0,
    wait_seconds: float = 10.0,
    poll_interval_seconds: float = 0.1,
    status_fn: Callable[[str, int, float, str, str | None], int] = http_status,
    monotonic_fn: Callable[[], float] = time.monotonic,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> dict[str, int]:
    if host not in {"127.0.0.1", "::1"}:
        raise AuthBoundaryError("coordinator auth preflight is restricted to loopback")
    if (
        port < 1
        or port > 65535
        or timeout <= 0
        or timeout > 120
        or wait_seconds <= 0
        or wait_seconds > 120
        or poll_interval_seconds <= 0
        or poll_interval_seconds > 10
    ):
        raise AuthBoundaryError("invalid coordinator port, timeout, or readiness wait")
    expected = {
        "anonymous_health": 200,
        "anonymous_inventory": 401,
        "authenticated_inventory": 200,
    }
    deadline = monotonic_fn() + wait_seconds
    attempts = 0
    token: str | None = None
    while True:
        attempts += 1
        def probe(path: str, bearer: str | None) -> int:
            remaining = deadline - monotonic_fn()
            if remaining <= 0:
                raise TimeoutError("coordinator readiness deadline expired between requests")
            return status_fn(host, port, min(timeout, remaining), path, bearer)

        try:
            if token is None:
                token = read_token(token_file)
            observed = {
                "anonymous_health": probe("/healthz", None),
                "anonymous_inventory": probe("/v1/inventory", None),
                "authenticated_inventory": probe("/v1/inventory", token),
            }
        except AuthBoundaryError as error:
            # The coordinator creates a missing token atomically before it
            # binds. Only ENOENT is a startup condition; a symlink, FIFO,
            # unsafe mode/owner, malformed value, or oversized token remains
            # an immediate credential failure.
            if not caused_by_missing_file(error):
                raise
            remaining = deadline - monotonic_fn()
            if remaining <= 0:
                raise AuthBoundaryError(
                    "coordinator token did not appear before the readiness deadline "
                    f"after {attempts} attempt(s)"
                ) from error
            sleep_fn(min(poll_interval_seconds, remaining))
            continue
        except (OSError, http.client.HTTPException) as error:
            if not isinstance(error, TRANSIENT_TRANSPORT_ERRORS):
                raise AuthBoundaryError(
                    f"coordinator returned a non-transient probe error: {type(error).__name__}"
                ) from error
            remaining = deadline - monotonic_fn()
            if remaining <= 0:
                raise AuthBoundaryError(
                    "coordinator did not become reachable before the readiness deadline "
                    f"after {attempts} attempt(s); last error class={type(error).__name__}"
                ) from error
            sleep_fn(min(poll_interval_seconds, remaining))
            continue
        if observed != expected:
            # A reachable endpoint with a wrong authorization contract is a
            # configuration/security failure, not a startup race. Fail closed
            # immediately instead of waiting for it to become acceptable.
            raise AuthBoundaryError(
                f"coordinator health/auth boundary mismatch: expected {expected}, got {observed}"
            )
        if monotonic_fn() > deadline:
            raise AuthBoundaryError(
                "coordinator boundary responses completed after the readiness deadline"
            )
        return observed


def http_inventory(host: str, port: int, timeout: float, bearer: str) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("GET", "/v1/inventory", headers={"Authorization": f"Bearer {bearer}"})
        response = connection.getresponse()
        payload = response.read(INVENTORY_MAX_BYTES + 1)
        return response.status, payload
    finally:
        connection.close()


def fetch_authenticated_inventory(
    *,
    token_file: Path,
    host: str = "127.0.0.1",
    port: int = 29876,
    timeout: float = 60.0,
    fetch_fn: Callable[[str, int, float, str], tuple[int, bytes]] = http_inventory,
) -> dict[str, object]:
    token = read_token(token_file)
    status, payload = fetch_fn(host, port, timeout, token)
    if status != 200:
        raise AuthBoundaryError(f"authenticated coordinator inventory returned HTTP {status}")
    if len(payload) > INVENTORY_MAX_BYTES:
        raise AuthBoundaryError("authenticated coordinator inventory is oversized")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthBoundaryError(f"authenticated coordinator inventory is invalid JSON: {error}") from error
    if not isinstance(value, dict):
        raise AuthBoundaryError("authenticated coordinator inventory JSON root must be an object")
    return value


def write_private_inventory(path: Path, inventory: dict[str, object]) -> None:
    parent, _absolute, name = open_private_parent(path)
    descriptor = -1
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(name, flags, 0o600, dir_fd=parent)
        payload = (json.dumps(inventory, indent=2, sort_keys=True) + "\n").encode("utf-8")
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.fsync(parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=29876)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--wait-seconds", type=float, default=10.0)
    parser.add_argument("--poll-interval-seconds", type=float, default=0.1)
    parser.add_argument("--inventory-output")
    args = parser.parse_args(argv)
    try:
        observed = check_boundary(
            token_file=Path(args.token_file),
            host=args.host,
            port=args.port,
            timeout=args.timeout,
            wait_seconds=args.wait_seconds,
            poll_interval_seconds=args.poll_interval_seconds,
        )
        if args.inventory_output:
            inventory = fetch_authenticated_inventory(
                token_file=Path(args.token_file),
                host=args.host,
                port=args.port,
                timeout=args.timeout,
            )
            write_private_inventory(Path(args.inventory_output), inventory)
    except (AuthBoundaryError, OSError, SecureIOError, http.client.HTTPException) as error:
        print(f"coordinator auth preflight failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, "statuses": observed}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
