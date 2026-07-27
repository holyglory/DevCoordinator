#!/usr/bin/env python3
"""Publish, inspect, or clear the broker-independent maintenance response."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import grp
import json
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
MODULE_ROOT = ROOT / "skills/codex-dev-coordinator/scripts"
if str(MODULE_ROOT) not in sys.path:
    sys.path.insert(0, str(MODULE_ROOT))

from devcoordinator.maintenance import (  # noqa: E402
    CONTROL_PLANE_MAINTENANCE_SCOPE,
    PUBLIC_MAINTENANCE_MESSAGE,
    activate_maintenance,
    clear_maintenance,
    load_maintenance_state,
)


ACCESS_GROUP = "devcoordinator-clients"
def _identity() -> tuple[int, int]:
    if os.geteuid() != 0:
        raise PermissionError("maintenance mode requires root")
    return 0, grp.getgrnam(ACCESS_GROUP).gr_gid


def _document(state: object | None, *, changed: bool) -> dict[str, object]:
    if state is None:
        return {"active": False, "changed": changed}
    return {
        "active": True,
        "changed": changed,
        "deployment_id": state.deployment_id,
        "message": state.message,
        "retry_after_seconds": state.retry_after_seconds,
        "started_at": state.started_at,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    activate = actions.add_parser("activate")
    activate.add_argument("--deployment-id", required=True)
    activate.add_argument(
        "--scope",
        required=True,
        choices=(CONTROL_PLANE_MAINTENANCE_SCOPE,),
        help="reserved control-plane scope; project operations must never activate this fence",
    )
    activate.add_argument("--retry-after-seconds", type=int, default=30)
    clear = actions.add_parser("clear")
    clear.add_argument("--deployment-id", required=True)
    actions.add_parser("status")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        uid, gid = _identity()
        if args.action == "activate":
            before = load_maintenance_state(
                expected_uid=uid, expected_gid=gid
            )
            state = activate_maintenance(
                expected_uid=uid,
                expected_gid=gid,
                deployment_id=args.deployment_id,
                scope=args.scope,
                message=PUBLIC_MAINTENANCE_MESSAGE,
                retry_after_seconds=args.retry_after_seconds,
                started_at=datetime.now(timezone.utc)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z"),
            )
            result = _document(state, changed=before is None)
        elif args.action == "clear":
            changed = clear_maintenance(
                expected_uid=uid,
                expected_gid=gid,
                deployment_id=args.deployment_id,
            )
            result = {"active": False, "changed": changed}
        else:
            result = _document(
                load_maintenance_state(
                    expected_uid=uid, expected_gid=gid
                ),
                changed=False,
            )
    except Exception as error:
        print(
            json.dumps(
                {"ok": False, "error": f"{type(error).__name__}: {error}"},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps({"ok": True, **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
