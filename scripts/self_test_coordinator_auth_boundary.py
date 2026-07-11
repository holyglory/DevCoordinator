#!/usr/bin/env python3
"""Optimized-Python-safe tests for the coordinator auth boundary preflight."""

from __future__ import annotations

import os
import signal
import tempfile
from pathlib import Path

from check_coordinator_auth_boundary import (
    AuthBoundaryError,
    check_boundary,
    fetch_authenticated_inventory,
    write_private_inventory,
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="coordinator-auth-boundary-") as raw:
        root = Path(raw).resolve(strict=True)
        token_file = root / "api-token"
        token_file.write_text("fixture-secret-token\n", encoding="utf-8")
        os.chmod(token_file, 0o600)
        calls: list[tuple[str, str | None]] = []

        def healthy(_host: str, _port: int, _timeout: float, path: str, bearer: str | None) -> int:
            calls.append((path, bearer))
            if path == "/healthz" and bearer is None:
                return 200
            if path == "/v1/inventory" and bearer is None:
                return 401
            if path == "/v1/inventory" and bearer == "fixture-secret-token":
                return 200
            return 500

        observed = check_boundary(token_file=token_file, status_fn=healthy)
        require(observed["anonymous_inventory"] == 401, "anonymous inventory was not proved closed")
        require(calls[-1] == ("/v1/inventory", "fixture-secret-token"), "token was not server-side only")

        fetch_calls: list[str] = []

        def inventory_fetch(_host: str, _port: int, _timeout: float, bearer: str) -> tuple[int, bytes]:
            fetch_calls.append(bearer)
            return 200, b'{"servers":[],"leases":[],"port_assignments":[]}\n'

        inventory = fetch_authenticated_inventory(token_file=token_file, fetch_fn=inventory_fetch)
        require(inventory["servers"] == [], "authenticated inventory body was not preserved")
        require(fetch_calls == ["fixture-secret-token"], "inventory fetch did not use the private token once")
        inventory_output = root / "post-cutover-inventory.json"
        write_private_inventory(inventory_output, inventory)
        require((inventory_output.stat().st_mode & 0o777) == 0o600, "inventory evidence is not mode 0600")
        require("fixture-secret-token" not in inventory_output.read_text(encoding="utf-8"), "token leaked to inventory evidence")
        try:
            write_private_inventory(inventory_output, inventory)
        except FileExistsError:
            pass
        else:
            raise AssertionError("inventory evidence writer overwrote an existing checkpoint")

        try:
            fetch_authenticated_inventory(
                token_file=token_file,
                fetch_fn=lambda *_args: (200, b'[]'),
            )
        except AuthBoundaryError as error:
            require("root must be an object" in str(error), "wrong inventory shape failure")
        else:
            raise AssertionError("non-object authenticated inventory was accepted")

        # Must catch a coordinator that accidentally leaves /v1 anonymous.
        def anonymous_leak(_host: str, _port: int, _timeout: float, path: str, bearer: str | None) -> int:
            if path == "/healthz":
                return 200
            if path == "/v1/inventory" and bearer is None:
                return 200
            return 200
        try:
            check_boundary(token_file=token_file, status_fn=anonymous_leak)
        except AuthBoundaryError as error:
            require("boundary mismatch" in str(error), "wrong auth failure classification")
            require("fixture-secret-token" not in str(error), "token leaked in auth failure")
        else:
            raise AssertionError("anonymous /v1 access was not detected")

        fifo = root / "token-fifo"
        os.mkfifo(fifo, 0o600)
        previous_handler = signal.signal(
            signal.SIGALRM,
            lambda _signum, _frame: (_ for _ in ()).throw(TimeoutError("FIFO open blocked")),
        )
        signal.alarm(2)
        try:
            try:
                check_boundary(token_file=fifo, status_fn=healthy)
            except AuthBoundaryError as error:
                require("regular file" in str(error), "FIFO had the wrong credential failure")
            else:
                raise AssertionError("FIFO credential path was accepted")
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous_handler)

    print("coordinator auth boundary self-test ok (works with Python optimization)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
