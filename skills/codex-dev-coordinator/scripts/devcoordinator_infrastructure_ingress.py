#!/usr/bin/env python3
"""Run or preflight the dedicated infrastructure observation ingress."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
import sys

from devcoordinator.infrastructure_ingress import (
    InfrastructureIngressError,
    run_ingress,
)
from devcoordinator.store import canonical_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Dedicated mTLS/JWS infrastructure observation ingress"
    )
    parser.add_argument("--config", required=True)
    parser.add_argument("--check-config", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    arguments = build_parser().parse_args(argv)
    try:
        result = run_ingress(
            Path(arguments.config),
            check_only=bool(arguments.check_config),
        )
    except InfrastructureIngressError as error:
        print(
            canonical_json(
                {
                    "ok": False,
                    "code": error.code,
                    "message": error.message,
                }
            ),
            file=sys.stderr,
        )
        return 1
    if result is not None:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
