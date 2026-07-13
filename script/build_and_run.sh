#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-run}"
APP_NAME="DevOpsBoard"
BUNDLE_ID="local.holyskills.codex-ops-console"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_ROOT="$ROOT_DIR/apps/DevOpsBoard"
APP_BUNDLE="$APP_ROOT/.build/app/DevOpsBoard.app"
APP_BINARY="$APP_BUNDLE/Contents/MacOS/DevOpsBoard"

pkill -x "$APP_NAME" >/dev/null 2>&1 || true

python3 "$APP_ROOT/Tools/package_app.py" \
  --configuration debug \
  --force \
  --json

launch_app() {
  /usr/bin/open -n "$APP_BUNDLE"
}

case "$MODE" in
  run)
    launch_app
    ;;
  --debug|debug)
    lldb -- "$APP_BINARY"
    ;;
  --logs|logs)
    launch_app
    /usr/bin/log stream --info --style compact --predicate "process == \"$APP_NAME\""
    ;;
  --telemetry|telemetry)
    launch_app
    /usr/bin/log stream --info --style compact --predicate "subsystem == \"$BUNDLE_ID\""
    ;;
  --verify|verify)
    launch_app
    sleep 1
    pgrep -x "$APP_NAME" >/dev/null
    ;;
  *)
    echo "usage: $0 [run|--debug|--logs|--telemetry|--verify]" >&2
    exit 2
    ;;
esac
