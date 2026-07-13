#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-run}"
APP_NAME="DevOpsBoard"
BUNDLE_ID="local.holyskills.codex-ops-console"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_ROOT="$ROOT_DIR/apps/DevOpsBoard"
APP_BUNDLE="$APP_ROOT/.build/app/DevOpsBoard.app"
APP_BINARY="$APP_BUNDLE/Contents/MacOS/DevOpsBoard"
PYTHON_COMMAND="python3"
SWIFT_COMMAND="swift"
PS_COMMAND="/bin/ps"
PGREP_COMMAND="/usr/bin/pgrep"
LOG_COMMAND="/usr/bin/log"
VERIFIER="$APP_ROOT/Tools/verify_launch_readiness.py"

run_tests() (
  set -euo pipefail
  cd "$ROOT_DIR"
  unset DEVOPS_BOARD_REGENERATE_CANONICAL_SNAPSHOTS
  unset DEVOPS_BOARD_SNAPSHOT_OUTPUT_DIR

  "$SWIFT_COMMAND" test --package-path "$APP_ROOT"
)

regenerate_snapshots() (
  set -euo pipefail
  cd "$ROOT_DIR"

  DEVOPS_BOARD_REGENERATE_CANONICAL_SNAPSHOTS=1 \
    DEVOPS_BOARD_SNAPSHOT_OUTPUT_DIR="$APP_ROOT/Artifacts/Canonical" \
    "$SWIFT_COMMAND" test \
      --package-path "$APP_ROOT" \
      --filter DevOpsBoardSnapshotTests.CanonicalSnapshotGenerationTests/testRegenerateCanonicalArtifactsWhenExplicitlyEnabled

  "$PYTHON_COMMAND" "$ROOT_DIR/scripts/public_artifact_guard.py"
  "$PYTHON_COMMAND" "$ROOT_DIR/scripts/verify_snapshot_artifacts.py"
)

if [[ "$MODE" == "test" || "$MODE" == "--test" ]]; then
  run_tests
  exit 0
fi

if [[ "$MODE" == "snapshots" || "$MODE" == "--snapshots" ]]; then
  regenerate_snapshots
  exit 0
fi

/usr/bin/pkill -u "$(id -u)" -x "$APP_NAME" >/dev/null 2>&1 || true

"$PYTHON_COMMAND" "$APP_ROOT/Tools/package_app.py" \
  --configuration debug \
  --force \
  --json

launch_app() {
  /usr/bin/open -n "$APP_BUNDLE"
}

verify_launch() (
  set -euo pipefail

  local capture_dir log_file capture_pid capture_ready pids app_pid app_start expected_executable expected_source_inventory coordinator_script
  capture_dir=""
  log_file=""
  capture_pid=""
  app_pid=""
  app_start=""
  expected_executable="$(cd "$(dirname "$APP_BINARY")" && pwd -P)/$(basename "$APP_BINARY")"
  coordinator_script="$APP_BUNDLE/Contents/Resources/skills/codex-dev-coordinator/scripts/dev_coordinator.py"
  expected_source_inventory="$("$PYTHON_COMMAND" "$VERIFIER" expected-inventory --coordinator-script "$coordinator_script")"

  pid_is_running() {
    local process_state
    process_state="$("$PS_COMMAND" -p "$1" -o stat= 2>/dev/null | /usr/bin/tr -d '[:space:]')"
    [[ -n "$process_state" && "$process_state" != Z* ]]
  }

  stop_capture() {
    local _
    if [[ -z "$capture_pid" ]]; then
      return
    fi
    if pid_is_running "$capture_pid"; then
      kill "$capture_pid" >/dev/null 2>&1 || true
      for _ in $(seq 1 40); do
        if ! pid_is_running "$capture_pid"; then
          break
        fi
        sleep 0.05
      done
    fi
    if pid_is_running "$capture_pid"; then
      kill -KILL "$capture_pid" >/dev/null 2>&1 || true
      for _ in $(seq 1 20); do
        if ! pid_is_running "$capture_pid"; then
          break
        fi
        sleep 0.05
      done
    fi
    if ! pid_is_running "$capture_pid"; then
      wait "$capture_pid" >/dev/null 2>&1 || true
    fi
  }

  cleanup_launch_verification() {
    local status=$?
    trap - EXIT
    set +e
    if [[ "$status" -ne 0 && -n "$app_pid" && -n "$app_start" ]]; then
      "$PYTHON_COMMAND" "$VERIFIER" terminate \
        --pid "$app_pid" \
        --expected-executable "$expected_executable" \
        --expected-start "$app_start" \
        --grace 2 >&2 || true
    fi
    stop_capture
    if [[ "$status" -eq 0 ]]; then
      if [[ -n "$capture_dir" ]]; then
        rm -rf "$capture_dir"
      fi
    elif [[ -n "$log_file" ]]; then
      echo "DevOps Board launch diagnostics retained at: $log_file" >&2
    fi
    exit "$status"
  }
  trap cleanup_launch_verification EXIT

  capture_dir="$(mktemp -d "${TMPDIR:-/tmp}/devops-board-launch-verify.XXXXXX")"
  chmod 700 "$capture_dir"
  log_file="$capture_dir/unified.log"
  : > "$log_file"
  chmod 600 "$log_file"

  if "$PGREP_COMMAND" -u "$(id -u)" -x "$APP_NAME" >/dev/null 2>&1; then
    echo "DevOps Board launch verification failed: previous app process did not exit" >&2
    exit 1
  fi

  NSUnbufferedIO=YES "$LOG_COMMAND" stream \
    --info \
    --style compact \
    --predicate "process == \"$APP_NAME\" && subsystem == \"$BUNDLE_ID\"" \
    > "$log_file" 2>&1 &
  capture_pid=$!

  capture_ready=false
  for _ in $(seq 1 40); do
    if ! pid_is_running "$capture_pid"; then
      echo "DevOps Board launch verification failed: unified-log capture exited during startup" >&2
      exit 1
    fi
    if [[ -s "$log_file" ]]; then
      capture_ready=true
      break
    fi
    sleep 0.05
  done
  if [[ "$capture_ready" != true ]]; then
    echo "DevOps Board launch verification failed: unified-log capture did not become ready" >&2
    exit 1
  fi

  launch_app

  for _ in $(seq 1 100); do
    if ! pid_is_running "$capture_pid"; then
      echo "DevOps Board launch verification failed: unified-log capture exited before app launch" >&2
      exit 1
    fi
    pids="$("$PGREP_COMMAND" -u "$(id -u)" -x "$APP_NAME" 2>/dev/null || true)"
    # One verification launch must identify exactly one fresh app process.
    set -- $pids
    if [[ $# -eq 1 ]]; then
      app_pid="$1"
      break
    fi
    if [[ $# -gt 1 ]]; then
      echo "DevOps Board launch verification failed: multiple fresh app processes were found" >&2
      exit 1
    fi
    sleep 0.05
  done
  if [[ -z "$app_pid" ]]; then
    echo "DevOps Board launch verification failed: fresh app process did not appear" >&2
    exit 1
  fi

  app_start="$("$PYTHON_COMMAND" "$VERIFIER" inspect \
    --pid "$app_pid" \
    --expected-executable "$expected_executable")"

  "$PYTHON_COMMAND" "$VERIFIER" wait \
    --log-file "$log_file" \
    --pid "$app_pid" \
    --expected-executable "$expected_executable" \
    --expected-start "$app_start" \
    --expected-source-inventory "$expected_source_inventory" \
    --expect-unfiltered-servers \
    --capture-pid "$capture_pid" \
    --timeout 30 \
    --stabilization 1.5
)

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
    verify_launch
    ;;
  *)
    echo "usage: $0 [run|--debug|--logs|--telemetry|--verify|--test|--snapshots]" >&2
    exit 2
    ;;
esac
