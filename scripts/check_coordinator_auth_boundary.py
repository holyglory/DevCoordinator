#!/usr/bin/env python3
"""Prove the production coordinator anonymous/authenticated HTTP boundary."""

from __future__ import annotations

import argparse
import http.client
import json
import sys
from pathlib import Path
from typing import Callable

from secure_cutover_io import SecureIOError, read_private_regular


class AuthBoundaryError(RuntimeError):
    pass


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
    status_fn: Callable[[str, int, float, str, str | None], int] = http_status,
) -> dict[str, int]:
    if host not in {"127.0.0.1", "::1"}:
        raise AuthBoundaryError("coordinator auth preflight is restricted to loopback")
    if port < 1 or port > 65535 or timeout <= 0 or timeout > 120:
        raise AuthBoundaryError("invalid coordinator port or timeout")
    try:
        token = read_private_regular(token_file, label="coordinator token").decode("utf-8").strip()
    except (SecureIOError, UnicodeDecodeError) as error:
        raise AuthBoundaryError(str(error)) from error
    if not token or len(token.encode("utf-8")) > 4096:
        raise AuthBoundaryError("coordinator token is empty or oversized")

    observed = {
        "anonymous_health": status_fn(host, port, timeout, "/healthz", None),
        "anonymous_inventory": status_fn(host, port, timeout, "/v1/inventory", None),
        "authenticated_inventory": status_fn(host, port, timeout, "/v1/inventory", token),
    }
    expected = {
        "anonymous_health": 200,
        "anonymous_inventory": 401,
        "authenticated_inventory": 200,
    }
    if observed != expected:
        raise AuthBoundaryError(
            f"coordinator health/auth boundary mismatch: expected {expected}, got {observed}"
        )
    return observed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=29876)
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args(argv)
    try:
        observed = check_boundary(
            token_file=Path(args.token_file),
            host=args.host,
            port=args.port,
            timeout=args.timeout,
        )
    except (AuthBoundaryError, OSError, http.client.HTTPException) as error:
        print(f"coordinator auth preflight failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, "statuses": observed}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
