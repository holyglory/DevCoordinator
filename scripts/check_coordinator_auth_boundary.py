#!/usr/bin/env python3
"""Prove the production Coordinator trusted-loopback HTTP boundary."""

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

from secure_cutover_io import SecureIOError, open_private_parent


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


def http_status(
    host: str,
    port: int,
    timeout: float,
    path: str,
    headers: dict[str, str] | None,
) -> int:
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("GET", path, headers=headers or {})
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def check_boundary(
    *,
    host: str = "127.0.0.1",
    port: int = 29876,
    timeout: float = 60.0,
    wait_seconds: float = 10.0,
    poll_interval_seconds: float = 0.1,
    status_fn: Callable[[str, int, float, str, dict[str, str] | None], int] = http_status,
    monotonic_fn: Callable[[], float] = time.monotonic,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> dict[str, int]:
    if host not in {"127.0.0.1", "::1"}:
        raise AuthBoundaryError("coordinator local-boundary preflight is restricted to loopback")
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
        "local_health": 200,
        "local_ready": 200,
        "foreign_host_ready": 400,
        "foreign_origin_ready": 403,
    }
    deadline = monotonic_fn() + wait_seconds
    attempts = 0
    while True:
        attempts += 1
        def probe(path: str, headers: dict[str, str] | None = None) -> int:
            remaining = deadline - monotonic_fn()
            if remaining <= 0:
                raise TimeoutError("coordinator readiness deadline expired between requests")
            return status_fn(host, port, min(timeout, remaining), path, headers)

        try:
            observed = {
                "local_health": probe("/healthz"),
                "local_ready": probe("/v1/ready"),
                "foreign_host_ready": probe(
                    "/v1/ready", {"Host": "external.example"}
                ),
                "foreign_origin_ready": probe(
                    "/v1/ready",
                    {
                        "Host": f"127.0.0.1:{port}",
                        "Origin": "https://external.example",
                    },
                ),
            }
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
            ready_status = observed["local_ready"]
            boundary_contract_ready = (
                observed["local_health"] == expected["local_health"]
                and observed["foreign_host_ready"] == expected["foreign_host_ready"]
                and observed["foreign_origin_ready"] == expected["foreign_origin_ready"]
            )
            if (
                boundary_contract_ready
                and type(ready_status) is int
                and 500 <= ready_status <= 599
            ):
                # A reachable API can publish its health/locality middleware
                # just before its local readiness handler finishes opening.
                # Retry only that exact, fail-closed startup shape. Re-probing
                # all four probes on the next attempt ensures a locality
                # boundary regression is never hidden by readiness polling.
                remaining = deadline - monotonic_fn()
                if remaining <= 0:
                    raise AuthBoundaryError(
                        "local coordinator endpoint did not become ready "
                        "before the readiness deadline "
                        f"after {attempts} attempt(s); last status=HTTP {ready_status}"
                    )
                sleep_fn(min(poll_interval_seconds, remaining))
                if monotonic_fn() >= deadline:
                    raise AuthBoundaryError(
                        "local coordinator endpoint did not become ready "
                        "before the readiness deadline "
                        f"after {attempts} attempt(s); last status=HTTP {ready_status}"
                    )
                continue
            # Any other reachable response is a configuration/security or
            # protocol-contract failure, not a startup race. That includes an
            # locality mismatch and non-ready 2xx/4xx responses.
            raise AuthBoundaryError(
                f"coordinator trusted-loopback boundary mismatch: expected {expected}, got {observed}"
            )
        if monotonic_fn() > deadline:
            raise AuthBoundaryError(
                "coordinator boundary responses completed after the readiness deadline"
            )
        return observed


def http_inventory(host: str, port: int, timeout: float) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("GET", "/v1/inventory", headers={"Host": f"127.0.0.1:{port}"})
        response = connection.getresponse()
        payload = response.read(INVENTORY_MAX_BYTES + 1)
        return response.status, payload
    finally:
        connection.close()


def fetch_local_inventory(
    *,
    host: str = "127.0.0.1",
    port: int = 29876,
    timeout: float = 60.0,
    fetch_fn: Callable[[str, int, float], tuple[int, bytes]] = http_inventory,
) -> dict[str, object]:
    status, payload = fetch_fn(host, port, timeout)
    if status != 200:
        raise AuthBoundaryError(f"local coordinator inventory returned HTTP {status}")
    if len(payload) > INVENTORY_MAX_BYTES:
        raise AuthBoundaryError("local coordinator inventory is oversized")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthBoundaryError(f"local coordinator inventory is invalid JSON: {error}") from error
    if not isinstance(value, dict):
        raise AuthBoundaryError("local coordinator inventory JSON root must be an object")
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
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=29876)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--wait-seconds", type=float, default=10.0)
    parser.add_argument("--poll-interval-seconds", type=float, default=0.1)
    parser.add_argument("--inventory-output")
    args = parser.parse_args(argv)
    try:
        observed = check_boundary(
            host=args.host,
            port=args.port,
            timeout=args.timeout,
            wait_seconds=args.wait_seconds,
            poll_interval_seconds=args.poll_interval_seconds,
        )
        if args.inventory_output:
            inventory = fetch_local_inventory(
                host=args.host,
                port=args.port,
                timeout=args.timeout,
            )
            write_private_inventory(Path(args.inventory_output), inventory)
    except (AuthBoundaryError, OSError, SecureIOError, http.client.HTTPException) as error:
        print(f"coordinator local-boundary preflight failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, "statuses": observed}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
