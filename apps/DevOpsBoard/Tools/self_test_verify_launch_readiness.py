#!/usr/bin/env python3
"""Deterministic recall and false-positive checks for launch readiness."""

from __future__ import annotations

import importlib.util
import os
import signal
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path
from types import ModuleType
from typing import Callable


SCRIPT = Path(__file__).with_name("verify_launch_readiness.py")
BUILD_SCRIPT = SCRIPT.parents[3] / "script" / "build_and_run.sh"
OPS_STORE = SCRIPT.parents[1] / "Sources" / "DevOpsBoard" / "OpsStore.swift"


def load_verifier() -> ModuleType:
    spec = importlib.util.spec_from_file_location("verify_launch_readiness", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load verify_launch_readiness.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


verifier = load_verifier()


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


class FakeTimeline:
    def __init__(self, on_sleep: Callable[[float], None] | None = None) -> None:
        self.now = 0.0
        self.on_sleep = on_sleep

    def monotonic(self) -> float:
        return self.now

    def sleep(self, duration: float) -> None:
        self.now += duration
        if self.on_sleep is not None:
            self.on_sleep(self.now)


def fixture_source_fingerprint(label: str) -> str:
    return verifier.source_fingerprint(f"/fixture/coordinator/{label}")


def unified_line(
    pid: int,
    outcome: str,
    loaded: int,
    total: int,
    *,
    sources: tuple[str, ...] | None = None,
    disabled: tuple[str, ...] = (),
    server_counts: tuple[tuple[str, int], ...] | None = None,
    managed: int = 0,
    visible: int | None = None,
    repositories: int = 0,
    repository_groups: int | None = None,
    unassigned_groups: int = 0,
    health: str | None = None,
    attention_items: int | None = None,
    resolution_targets: int | None = None,
    generic_attention: bool = False,
) -> str:
    if sources is None:
        sources = tuple(fixture_source_fingerprint(f"source-{index}") for index in range(loaded))
    visible = managed if visible is None else visible
    repository_groups = repositories if repository_groups is None else repository_groups
    if health is None:
        if outcome == "completed" and loaded > 0:
            health = "nominal" if loaded == total else "degraded"
        else:
            health = "unavailable"
    if attention_items is None:
        attention_items = 0 if health == "nominal" else 1
    if resolution_targets is None:
        resolution_targets = 0 if health == "nominal" else 1
    if server_counts is None:
        server_counts = tuple(
            (fingerprint, managed if len(sources) == 1 else 0)
            for fingerprint in sources
        )
    source_evidence = ",".join(sources) or "none"
    disabled_evidence = ",".join(disabled) or "none"
    server_count_evidence = ",".join(
        f"{fingerprint}:{count}" for fingerprint, count in server_counts
    ) or "none"
    return (
        "2026-07-13 17:10:00.000 I  DevOpsBoard"
        f"[{pid}:abc123] [local.holyskills.codex-ops-console:inventory] "
        f"Inventory refresh {outcome} pid={pid} loaded={loaded} total={total} "
        f"sources={source_evidence} disabled={disabled_evidence} server_counts={server_count_evidence} "
        f"managed={managed} visible={visible} repositories={repositories} "
        f"repository_groups={repository_groups} unassigned_groups={unassigned_groups} "
        f"health={health} attention_items={attention_items} "
        f"resolution_targets={resolution_targets} "
        f"generic_attention={'true' if generic_attention else 'false'}\n"
    )


def run_wait(
    log_path: Path,
    *,
    expected_pid: int,
    expected_start: str = "fixture-start",
    timeline: FakeTimeline | None = None,
    identity_reader: Callable[[int], object | None] | None = None,
    capture_pid: int | None = None,
    is_alive: Callable[[int], bool] = lambda _pid: True,
    expected_source_fingerprint: str | None = None,
    expected_source_inventory: str | None = None,
    require_unfiltered_servers: bool = False,
) -> object:
    timeline = timeline or FakeTimeline()
    expected = verifier.ProcessIdentity(
        pid=expected_pid,
        executable="/fixture/DevOpsBoard",
        start=expected_start,
    )
    identity_reader = identity_reader or (lambda _pid: expected)
    return verifier.wait_for_inventory_readiness(
        log_path=log_path,
        expected_identity=expected,
        timeout=0.2,
        poll_interval=0.05,
        stabilization=0.1,
        capture_pid=capture_pid,
        expected_source_fingerprint=expected_source_fingerprint,
        expected_source_inventory=expected_source_inventory,
        require_unfiltered_servers=require_unfiltered_servers,
        identity_reader=identity_reader,
        is_alive=is_alive,
        monotonic=timeline.monotonic,
        sleep=timeline.sleep,
    )


def expect_failure(action: Callable[[], object], contains: str, message: str) -> None:
    try:
        action()
    except verifier.LaunchReadinessError as error:
        check(contains in str(error), f"{message}: expected {contains!r}, got {error!r}")
        return
    raise AssertionError(message)


def check_build_script_wiring() -> None:
    source = BUILD_SCRIPT.read_text(encoding="utf-8")
    start = source.find("verify_launch() (")
    end = source.find("\ncase \"$MODE\" in", start)
    check(start >= 0 and end > start, "build script does not define the launch-readiness gate")
    gate = source[start:end]
    capture = gate.find('"$LOG_COMMAND" stream')
    launch = gate.find("launch_app")
    pid = gate.find('app_pid="$1"')
    verifier_call = gate.find('"$VERIFIER" inspect')
    source_expectation = gate.find('"$VERIFIER" expected-inventory')
    check(source_expectation >= 0, "launch gate does not derive the OS-account source expectation")
    check(source_expectation < launch, "source expectation is derived after app launch")
    check(capture >= 0, "launch-readiness gate does not start a unified-log capture")
    check(launch > capture, "app launches before the fresh unified-log capture starts")
    check(pid > launch, "launch-readiness gate does not bind the fresh app PID")
    check(verifier_call > pid, "launch-readiness helper runs before the fresh app PID is known")
    check("--capture-pid \"$capture_pid\"" in gate, "launch gate does not monitor its log capture")
    check("--expected-executable \"$expected_executable\"" in gate, "launch gate does not bind the exact executable")
    check("--expected-start \"$app_start\"" in gate, "launch gate does not bind process start identity")
    check(
        '--expected-source-inventory "$expected_source_inventory"' in gate,
        "launch gate does not require source-bound packaged-helper inventory evidence",
    )
    check("--expect-unfiltered-servers" in gate, "launch gate does not verify clean-launch server visibility")
    check("--stabilization 1.5" in gate, "launch gate lacks the sustained-health window")
    check(" terminate \\\n" in gate, "failed launch does not invoke identity-bound cleanup")
    check(
        '/usr/bin/pkill -u "$(id -u)" -x "$APP_NAME"' in source,
        "initial app cleanup is not user-scoped",
    )
    verify_case = source[source.find("--verify|verify)") :]
    check("verify_launch" in verify_case, "--verify is not wired to inventory readiness")
    check("sleep 1" not in verify_case, "--verify regressed to a timed process-existence check")

    syntax = subprocess.run(
        ["/bin/bash", "-n", str(BUILD_SCRIPT)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    check(syntax.returncode == 0, f"build script is not valid Bash: {syntax.stderr}")


def check_production_telemetry_wiring() -> None:
    source = OPS_STORE.read_text(encoding="utf-8")
    required = {
        "presentation snapshot": "let snapshot = presentationSnapshot",
        "concrete item count": "let attentionItems = snapshot.attentionItemCount",
        "working target count": "let resolutionTargets = snapshot.resolutionTargetIDs.count",
        "generic-copy comparison": ".localizedCaseInsensitiveCompare(",
    }
    missing = [label for label, token in required.items() if token not in source]
    check(
        not missing,
        "production inventory telemetry is missing attention-readiness bindings: "
        + ", ".join(missing),
    )
    emitted_fields = (
        " health=\\(health, privacy: .public)",
        " attention_items=\\(attentionItems, privacy: .public)",
        " resolution_targets=\\(resolutionTargets, privacy: .public)",
        " generic_attention=\\(genericAttention, privacy: .public)",
    )
    for field in emitted_fields:
        check(
            source.count(field) == 2,
            f"completed and failed inventory telemetry do not both emit {field.strip()}",
        )


def write_executable(path: Path, source: str) -> None:
    path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
    path.chmod(0o755)


def check_shell_behavior_harness(temp: Path) -> None:
    source = BUILD_SCRIPT.read_text(encoding="utf-8")
    start = source.find("verify_launch() (")
    end = source.find("\ncase \"$MODE\" in", start)
    check(start >= 0 and end > start, "could not extract launch gate for shell harness")
    gate = source[start:end]

    harness_root = temp / "shell-harness"
    harness_root.mkdir()
    app_binary = harness_root / "bundle" / "DevOpsBoard"
    app_binary.parent.mkdir()
    app_binary.write_text("fixture\n", encoding="utf-8")
    state = harness_root / "app-state"
    terminated = harness_root / "terminated"

    fake_pgrep = harness_root / "pgrep"
    write_executable(
        fake_pgrep,
        """
        #!/usr/bin/env python3
        import os
        from pathlib import Path

        if Path(os.environ["HARNESS_STATE"]).exists():
            print("4242")
            raise SystemExit(0)
        raise SystemExit(1)
        """,
    )
    fake_log = harness_root / "log"
    write_executable(
        fake_log,
        """
        #!/bin/bash
        trap 'exit 0' TERM INT
        echo 'Filtering the log data using the fixture predicate'
        while :; do
          sleep 0.1
        done
        """,
    )
    fake_python = harness_root / "python"
    write_executable(
        fake_python,
        """
        #!/usr/bin/env python3
        import os
        from pathlib import Path
        import sys

        command = sys.argv[2]
        state = Path(os.environ["HARNESS_STATE"])
        if command == "expected-inventory":
            if "--coordinator-script" not in sys.argv:
                raise SystemExit(2)
            print("a" * 64 + ":16")
            raise SystemExit(0)
        if command == "inspect":
            if not state.exists():
                raise SystemExit(1)
            print("Mon Jul 13 17:00:00 2026")
            raise SystemExit(0)
        if command == "wait":
            expected_index = sys.argv.index("--expected-source-inventory")
            if sys.argv[expected_index + 1] != "a" * 64 + ":16" or "--expect-unfiltered-servers" not in sys.argv:
                print("source readiness arguments missing", file=sys.stderr)
                raise SystemExit(2)
            if os.environ["HARNESS_WAIT_RESULT"] == "success":
                print("fixture ready")
                raise SystemExit(0)
            print("planned readiness failure", file=sys.stderr)
            raise SystemExit(1)
        if command == "terminate":
            if "--expected-start" not in sys.argv or "--expected-executable" not in sys.argv:
                print("cleanup identity missing", file=sys.stderr)
                raise SystemExit(2)
            state.unlink(missing_ok=True)
            Path(os.environ["HARNESS_TERMINATED"]).write_text("terminated\\n", encoding="utf-8")
            print("fixture exact identity terminated")
            raise SystemExit(0)
        raise SystemExit(64)
        """,
    )
    harness = harness_root / "run-gate.sh"
    harness.write_text(
        "\n".join(
            [
                "#!/bin/bash",
                "set -euo pipefail",
                'APP_NAME="DevOpsBoard"',
                'BUNDLE_ID="fixture.devops-board"',
                f'APP_BUNDLE="{app_binary.parent}"',
                f'APP_BINARY="{app_binary}"',
                f'PYTHON_COMMAND="{fake_python}"',
                'PS_COMMAND="/bin/ps"',
                f'PGREP_COMMAND="{fake_pgrep}"',
                f'LOG_COMMAND="{fake_log}"',
                'VERIFIER="/fixture/verifier.py"',
                'launch_app() { printf "alive\\n" > "$HARNESS_STATE"; }',
                gate,
                "verify_launch",
                "",
            ]
        ),
        encoding="utf-8",
    )
    harness.chmod(0o755)

    common_env = {
        **os.environ,
        "HARNESS_STATE": str(state),
        "HARNESS_TERMINATED": str(terminated),
        "TMPDIR": str(harness_root),
    }
    success = subprocess.run(
        ["/bin/bash", str(harness)],
        env={**common_env, "HARNESS_WAIT_RESULT": "success"},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    check(success.returncode == 0, f"shell success fixture failed: {success.stderr}")
    check(state.exists(), "successful launch gate terminated the ready app")
    check(not terminated.exists(), "successful launch gate invoked failure cleanup")
    check(
        not list(harness_root.glob("devops-board-launch-verify.*")),
        "successful launch gate retained its temporary log capture",
    )

    state.unlink()
    failed = subprocess.run(
        ["/bin/bash", str(harness)],
        env={**common_env, "HARNESS_WAIT_RESULT": "failure"},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    check(failed.returncode != 0, "failed readiness returned shell success")
    check(not state.exists(), "failed readiness left the launched app running")
    check(terminated.exists(), "failed readiness did not invoke exact-identity termination")
    check("planned readiness failure" in failed.stderr, "readiness diagnostics were lost")
    prefix = "DevOps Board launch diagnostics retained at: "
    diagnostic_lines = [line for line in failed.stderr.splitlines() if line.startswith(prefix)]
    check(len(diagnostic_lines) == 1, f"retained diagnostic path was not reported: {failed.stderr}")
    diagnostic = Path(diagnostic_lines[0][len(prefix) :])
    check(diagnostic.is_file(), "reported failed-launch diagnostic file does not exist")
    check(diagnostic.stat().st_mode & 0o777 == 0o600, "failed-launch diagnostic is not private")


def main() -> int:
    check_build_script_wiring()
    check_production_telemetry_wiring()
    check(verifier.process_state_is_alive("Ss+"), "ordinary sleeping process state was rejected")
    check(not verifier.process_state_is_alive("Z+"), "zombie process state was treated as alive")
    check(not verifier.process_state_is_alive("  "), "empty process state was treated as alive")
    with tempfile.TemporaryDirectory(prefix="devops-board-launch-readiness-") as raw_temp:
        # This fixture owns the temporary root. Canonicalize it before deriving
        # identity paths so macOS's platform-managed /var -> /private/var alias
        # cannot make normalized production paths disagree with lexical fixture
        # expectations. Operator-provided paths remain subject to their normal
        # production symlink policy; only this test-created root is resolved.
        temp = Path(raw_temp).resolve(strict=True)

        account_home = temp / "account-home"
        canonical_source = account_home / ".codex/agent-coordinator"
        canonical_source.mkdir(parents=True)
        (canonical_source / "state.json").write_text(
            '{"servers":{},"leases":{},"history":[],"port_assignments":{}}\n',
            encoding="utf-8",
        )
        canonical_fingerprint = verifier.expected_automatic_source_fingerprint(
            account_home=account_home,
            environment={},
        )
        check(
            canonical_fingerprint == verifier.source_fingerprint(canonical_source),
            "automatic OS-account source fingerprint did not use the canonical account home",
        )
        check(
            canonical_fingerprint is not None and len(canonical_fingerprint) == 64,
            "automatic source fingerprint is not exact 64-hex evidence",
        )
        absent_home = temp / "account-without-coordinator"
        absent_home.mkdir()
        check(
            verifier.expected_automatic_source_fingerprint(account_home=absent_home, environment={})
            == verifier.source_fingerprint(absent_home / ".codex/agent-coordinator"),
            "the deterministic account-store source disappeared before first initialization",
        )
        original_stat = verifier.os.stat

        def denied_stat(_path: object) -> object:
            raise PermissionError(13, "fixture denied", str(canonical_source))

        verifier.os.stat = denied_stat
        try:
            try:
                verifier.observable_entry_exists(canonical_source)
            except verifier.LaunchReadinessError as error:
                check(
                    str(canonical_source) not in str(error),
                    "observer failure leaked the private automatic-source path",
                )
            else:
                raise AssertionError("permission-denied source observation was treated as absent")
        finally:
            verifier.os.stat = original_stat

        # Must-catch: legacy Codex/Claude/Parall state homes are importer inputs,
        # not independent Board authorities. Polling all four recreates duplicate
        # projects and duplicate Docker sampling. An explicit configured alias is
        # still canonicalized to the one selected account store.
        multi_home = temp / "multi-instance-account"
        multi_sources = (
            multi_home / ".codex/agent-coordinator",
            multi_home / ".claude/agent-coordinator",
            multi_home / "Library/Application Support/Parall/Codex A/.codex/agent-coordinator",
            multi_home / "Library/Application Support/Parall/Codex B/.codex/agent-coordinator",
        )
        source_counts = (16, 3, 0, 2)
        for source, count in zip(multi_sources, source_counts):
            source.mkdir(parents=True)
            (source / "state.json").write_text(
                '{"fixture_server_count":' + str(count) + '}\n',
                encoding="utf-8",
            )
        alias = temp / "codex-source-alias"
        alias.symlink_to(multi_sources[0], target_is_directory=True)
        discovered = verifier.automatic_source_paths(
            account_home=multi_home,
            environment={},
        )
        check(
            discovered == (multi_sources[0],),
            f"legacy instance homes leaked into the active account-store set: {discovered!r}",
        )
        check(
            verifier.automatic_source_paths(
                account_home=multi_home,
                environment={"CODEX_AGENT_COORDINATOR_HOME": str(alias)},
            )
            == (multi_sources[0],),
            "configured account-store alias was not canonicalized to one physical source",
        )

        fake_coordinator = temp / "fixture-coordinator.py"
        write_executable(
            fake_coordinator,
            """
            #!/usr/bin/env python3
            import json
            import os
            from pathlib import Path

            home = Path(os.environ["CODEX_AGENT_COORDINATOR_HOME"])
            state = json.loads((home / "state.json").read_text())
            count = state["fixture_server_count"]
            unassigned_count = state.get("fixture_unassigned_server_count", 0)
            payload = {"coordinator_home": str(home), "servers": [{}] * count}
            if unassigned_count:
                unassigned = [
                    {
                        "resource_kind": "server",
                        "resource_id": f"unassigned-{index}",
                        "reason_code": "missing_repo",
                    }
                    for index in range(unassigned_count)
                ]
                payload.update(
                    {
                        "schema_version": 2,
                        "resources": {
                            "servers": [
                                {"server_definition_id": f"server-{index}"}
                                for index in range(count)
                            ]
                        },
                        "unassigned_resources": unassigned,
                        # The normalized API may repeat the same incident in
                        # both collections; the Board presents it only once.
                        "lifecycle_violations": unassigned,
                    }
                )
            print(json.dumps(payload))
            """,
        )
        measured_inventory = verifier.collect_expected_source_inventory(
            coordinator_script=fake_coordinator,
            source_paths=discovered,
        )
        expected_count_by_fingerprint = {
            verifier.source_fingerprint(path): count
            for path, count in zip(discovered, source_counts)
        }
        check(
            dict(measured_inventory) == expected_count_by_fingerprint,
            "packaged-helper preflight did not bind each source to its real server count",
        )
        (multi_sources[0] / "state.json").write_text(
            '{"fixture_server_count":18,"fixture_unassigned_server_count":1}\n',
            encoding="utf-8",
        )
        normalized_with_unassigned = verifier.collect_expected_source_inventory(
            coordinator_script=fake_coordinator,
            source_paths=discovered,
        )
        check(
            dict(normalized_with_unassigned) == {verifier.source_fingerprint(discovered[0]): 19},
            "packaged-helper preflight did not count the normalized unassigned server shown by the Board",
        )
        normalized_fingerprint = verifier.source_fingerprint(discovered[0])
        normalized_inventory_argument = verifier.format_expected_source_inventory(
            normalized_with_unassigned
        )
        normalized_unassigned_ready = temp / "normalized-unassigned-ready.log"
        normalized_unassigned_ready.write_text(
            unified_line(
                4088,
                "completed",
                1,
                1,
                sources=(normalized_fingerprint,),
                server_counts=((normalized_fingerprint, 19),),
                managed=19,
                visible=19,
                repositories=9,
                unassigned_groups=1,
            ),
            encoding="utf-8",
        )
        check(
            run_wait(
                normalized_unassigned_ready,
                expected_pid=4088,
                expected_source_inventory=normalized_inventory_argument,
                require_unfiltered_servers=True,
            ).managed_servers
            == 19,
            "normalized definitions plus one unassigned server did not pass readiness at the measured count",
        )
        normalized_unassigned_dropped = temp / "normalized-unassigned-dropped.log"
        normalized_unassigned_dropped.write_text(
            unified_line(
                4089,
                "completed",
                1,
                1,
                sources=(normalized_fingerprint,),
                server_counts=((normalized_fingerprint, 18),),
                managed=18,
                visible=18,
                repositories=9,
                unassigned_groups=1,
            ),
            encoding="utf-8",
        )
        expect_failure(
            lambda: run_wait(
                normalized_unassigned_dropped,
                expected_pid=4089,
                expected_source_inventory=normalized_inventory_argument,
                require_unfiltered_servers=True,
            ),
            "did not match packaged-helper preflight",
            "dropping the normalized unassigned server passed readiness",
        )
        measured_inventory_argument = verifier.format_expected_source_inventory(measured_inventory)

        # Must-catch: the app successfully loads a valid-but-empty coordinator
        # under an inherited pseudo-home instead of the existing OS-account
        # source. A source-count-only gate previously accepted this incident.
        wrong_empty_fingerprint = fixture_source_fingerprint("wrong-valid-empty-home")
        wrong_empty = temp / "wrong-valid-empty-home.log"
        wrong_empty_line = unified_line(
            4090,
            "completed",
            1,
            1,
            sources=(wrong_empty_fingerprint,),
            managed=0,
            visible=0,
        )
        wrong_empty.write_text(wrong_empty_line, encoding="utf-8")
        check(str(account_home) not in wrong_empty_line, "telemetry leaked a private source path")
        expect_failure(
            lambda: run_wait(
                wrong_empty,
                expected_pid=4090,
                expected_source_fingerprint=canonical_fingerprint,
                require_unfiltered_servers=True,
            ),
            "neither loaded nor explicitly disabled",
            "wrong valid empty coordinator home passed source-bound readiness",
        )

        # False-positive control: an existing but genuinely empty automatic
        # source is ready when its identity was loaded and zero rows are shown.
        legitimate_empty = temp / "legitimate-empty-home.log"
        legitimate_empty.write_text(
            unified_line(
                4091,
                "completed",
                1,
                1,
                sources=(canonical_fingerprint,),
                managed=0,
                visible=0,
            ),
            encoding="utf-8",
        )
        empty_ready = run_wait(
            legitimate_empty,
            expected_pid=4091,
            expected_source_fingerprint=canonical_fingerprint,
            require_unfiltered_servers=True,
        )
        check(
            empty_ready.managed_servers == 0 and empty_ready.visible_servers == 0,
            "legitimate empty automatic source did not pass readiness",
        )
        check(
            empty_ready.health == "nominal"
            and empty_ready.attention_items == 0
            and empty_ready.resolution_targets == 0
            and not empty_ready.generic_attention,
            "nominal inventory did not retain an empty attention contract",
        )

        # False-positive control: a genuinely unhealthy live service is ready
        # when the Board exposes one concrete issue and a working review route.
        actionable_unhealthy = temp / "actionable-unhealthy-service.log"
        actionable_unhealthy.write_text(
            unified_line(
                4161,
                "completed",
                1,
                1,
                managed=2,
                visible=2,
                repositories=1,
                health="unhealthy",
                attention_items=1,
                resolution_targets=1,
            ),
            encoding="utf-8",
        )
        actionable_ready = run_wait(actionable_unhealthy, expected_pid=4161)
        check(
            actionable_ready.health == "unhealthy"
            and actionable_ready.attention_items == 1
            and actionable_ready.resolution_targets == 1
            and not actionable_ready.generic_attention,
            "a concrete unhealthy service with a review target was rejected",
        )

        # Must-catch the user-visible incident: the red banner repeated
        # "Action or resource requires attention" as both title and summary,
        # but named no item and offered no contextual resolution.
        generic_unhealthy = temp / "generic-unhealthy-attention.log"
        generic_unhealthy.write_text(
            unified_line(
                4162,
                "completed",
                1,
                1,
                managed=2,
                visible=2,
                repositories=1,
                health="unhealthy",
                attention_items=0,
                resolution_targets=0,
                generic_attention=True,
            ),
            encoding="utf-8",
        )
        expect_failure(
            lambda: run_wait(generic_unhealthy, expected_pid=4162),
            "generic duplicated attention",
            "the production-shaped generic attention banner passed readiness",
        )

        unexplained_unhealthy = temp / "unexplained-unhealthy-state.log"
        unexplained_unhealthy.write_text(
            unified_line(
                4163,
                "completed",
                1,
                1,
                health="unhealthy",
                attention_items=0,
                resolution_targets=1,
            ),
            encoding="utf-8",
        )
        expect_failure(
            lambda: run_wait(unexplained_unhealthy, expected_pid=4163),
            "without a concrete attention item",
            "unhealthy state with no identified issue passed readiness",
        )

        unactionable_unhealthy = temp / "unactionable-unhealthy-state.log"
        unactionable_unhealthy.write_text(
            unified_line(
                4164,
                "completed",
                1,
                1,
                health="unhealthy",
                attention_items=1,
                resolution_targets=0,
            ),
            encoding="utf-8",
        )
        expect_failure(
            lambda: run_wait(unactionable_unhealthy, expected_pid=4164),
            "without a resolution target",
            "identified unhealthy state with no contextual route passed readiness",
        )

        # Multiple issues may intentionally share one Review Issues route; the
        # detector must not require one button per item.
        shared_review_target = temp / "shared-attention-review-target.log"
        shared_review_target.write_text(
            unified_line(
                4165,
                "completed",
                1,
                1,
                health="unhealthy",
                attention_items=3,
                resolution_targets=1,
            ),
            encoding="utf-8",
        )
        shared_ready = run_wait(shared_review_target, expected_pid=4165)
        check(
            shared_ready.attention_items == 3 and shared_ready.resolution_targets == 1,
            "one real review route shared by multiple issues was rejected",
        )

        # A running action is intentionally non-nominal and routes to Activity;
        # it must not be rejected merely because it is not an error.
        actionable_busy = temp / "actionable-busy-state.log"
        actionable_busy.write_text(
            unified_line(
                4167,
                "completed",
                1,
                1,
                health="busy",
                attention_items=1,
                resolution_targets=1,
            ),
            encoding="utf-8",
        )
        busy_ready = run_wait(actionable_busy, expected_pid=4167)
        check(
            busy_ready.health == "busy"
            and busy_ready.attention_items == 1
            and busy_ready.resolution_targets == 1,
            "an in-progress action with an Activity target was rejected",
        )

        nominal_with_phantom_attention = temp / "nominal-phantom-attention.log"
        nominal_with_phantom_attention.write_text(
            unified_line(
                4166,
                "completed",
                1,
                1,
                health="nominal",
                attention_items=1,
                resolution_targets=1,
            ),
            encoding="utf-8",
        )
        expect_failure(
            lambda: run_wait(nominal_with_phantom_attention, expected_pid=4166),
            "nominal health with attention_items=1 resolution_targets=1",
            "nominal state with phantom attention passed readiness",
        )

        # Must-catch: correct source identity is not enough when the direct
        # helper measured real rows and the Board decoded/merged zero of them.
        dropped_real_rows = temp / "dropped-real-rows.log"
        dropped_real_rows.write_text(
            unified_line(
                4094,
                "completed",
                1,
                1,
                sources=(canonical_fingerprint,),
                managed=0,
                visible=0,
            ),
            encoding="utf-8",
        )
        expect_failure(
            lambda: run_wait(
                dropped_real_rows,
                expected_pid=4094,
                expected_source_inventory=f"{canonical_fingerprint}:16",
                require_unfiltered_servers=True,
            ),
            "did not match packaged-helper preflight",
            "populated source decoded as zero servers passed readiness",
        )

        account_loaded_counts = tuple(measured_inventory)
        account_store_only = temp / "account-store-only.log"
        account_store_only.write_text(
            unified_line(
                4095,
                "completed",
                1,
                1,
                sources=tuple(fingerprint for fingerprint, _count in account_loaded_counts),
                server_counts=account_loaded_counts,
                managed=source_counts[0],
                visible=source_counts[0],
            ),
            encoding="utf-8",
        )
        check(
            run_wait(
                account_store_only,
                expected_pid=4095,
                expected_source_inventory=measured_inventory_argument,
                require_unfiltered_servers=True,
            ).loaded
            == 1,
            "normalized account-store source did not pass source-bound readiness",
        )

        legacy_loaded_counts = tuple(
            sorted(
                (verifier.source_fingerprint(path), count)
                for path, count in zip(multi_sources, source_counts)
            )
        )
        legacy_sources_polled = temp / "legacy-sources-polled.log"
        legacy_sources_polled.write_text(
            unified_line(
                4096,
                "completed",
                4,
                4,
                sources=tuple(fingerprint for fingerprint, _count in legacy_loaded_counts),
                server_counts=legacy_loaded_counts,
                managed=sum(source_counts),
                visible=sum(source_counts),
            ),
            encoding="utf-8",
        )
        expect_failure(
            lambda: run_wait(
                legacy_sources_polled,
                expected_pid=4096,
                expected_source_inventory=measured_inventory_argument,
            ),
            "3 unexpected coordinator source(s)",
            "legacy Codex/Claude/Parall homes passed as independent Board sources",
        )

        missing_account_store = temp / "missing-account-store.log"
        # Bind this fixture to an explicitly legacy source. Selecting the last
        # hash after sorting is nondeterministic with respect to source kind and
        # can accidentally select the canonical account store.
        legacy_fingerprint = verifier.source_fingerprint(multi_sources[1])
        legacy_count = source_counts[1]
        missing_account_store.write_text(
            unified_line(
                4097,
                "completed",
                1,
                1,
                sources=(legacy_fingerprint,),
                server_counts=((legacy_fingerprint, legacy_count),),
                managed=legacy_count,
                visible=legacy_count,
            ),
            encoding="utf-8",
        )
        expect_failure(
            lambda: run_wait(
                missing_account_store,
                expected_pid=4097,
                expected_source_inventory=measured_inventory_argument,
            ),
            "1 automatic OS-account coordinator source(s)",
            "a legacy instance substituted for the account store",
        )

        # Explicitly disabling the automatic source is intentional. Another
        # loaded source keeps the Board usable and the gate must not override
        # that persisted user choice.
        explicitly_disabled = temp / "explicitly-disabled.log"
        explicitly_disabled.write_text(
            unified_line(
                4092,
                "completed",
                1,
                1,
                sources=(fixture_source_fingerprint("enabled-alternate"),),
                disabled=(canonical_fingerprint,),
            ),
            encoding="utf-8",
        )
        disabled_ready = run_wait(
            explicitly_disabled,
            expected_pid=4092,
            expected_source_fingerprint=canonical_fingerprint,
        )
        check(disabled_ready.loaded == 1, "explicitly disabled automatic source caused a false failure")

        # Must-catch: an unmeasured helper preflight cannot silently bless a
        # loaded normalized account source.
        unmeasured_loaded = temp / "unmeasured-loaded-source.log"
        unmeasured_loaded.write_text(
            unified_line(
                4098,
                "completed",
                1,
                1,
                sources=(canonical_fingerprint,),
            ),
            encoding="utf-8",
        )
        expect_failure(
            lambda: run_wait(
                unmeasured_loaded,
                expected_pid=4098,
                expected_source_inventory=f"{canonical_fingerprint}:?",
            ),
            "could not measure a loaded automatic source",
            "unmeasured loaded source passed packaged-helper readiness",
        )
        # No account source means there is no identity requirement. This is a
        # separate control from a present-but-empty account source.
        no_account_requirement = temp / "no-account-source.log"
        no_account_requirement.write_text(
            unified_line(4093, "completed", 1, 1, sources=(wrong_empty_fingerprint,)),
            encoding="utf-8",
        )
        check(
            run_wait(
                no_account_requirement,
                expected_pid=4093,
                expected_source_fingerprint=None,
            ).loaded
            == 1,
            "absent account source incorrectly constrained another loaded source",
        )

        # Common intentional state: one coordinator source loaded while Docker
        # is degraded. Readiness is source-level, so the capability warning must
        # not be mistaken for a launch failure.
        degraded = temp / "docker-degraded.log"
        degraded.write_text(
            "2026-07-13 17:10:00.000 E  DevOpsBoard[4101:abc123] "
            "[local.holyskills.codex-ops-console:inventory] Docker inventory degraded\n"
            + unified_line(4101, "completed", 1, 1),
            encoding="utf-8",
        )
        ready = run_wait(degraded, expected_pid=4101)
        check(ready.loaded == 1 and ready.total == 1, "Docker-degraded loaded source did not pass readiness")

        # Must-catch: the app is alive but its only source failed, exactly like
        # the user-visible Inventory unavailable incident.
        failed = temp / "failed-source.log"
        failed.write_text(unified_line(4102, "failed", 0, 1), encoding="utf-8")
        expect_failure(
            lambda: run_wait(failed, expected_pid=4102),
            "inventory refresh failed",
            "alive app with a failed source passed launch readiness",
        )

        # A fresh capture can still receive delayed messages from the previous
        # process. Its success must not satisfy the newly launched PID.
        stale = temp / "stale-success.log"
        stale.write_text(unified_line(3999, "completed", 1, 1), encoding="utf-8")
        expect_failure(
            lambda: run_wait(stale, expected_pid=4103),
            "timed out",
            "wrong/stale PID satisfied launch readiness",
        )

        # A stale success before the current process's failure must be ignored;
        # the correct-PID failure remains authoritative.
        mixed = temp / "stale-then-current-failure.log"
        mixed.write_text(
            unified_line(3999, "completed", 1, 1)
            + unified_line(4104, "failed", 0, 1),
            encoding="utf-8",
        )
        expect_failure(
            lambda: run_wait(mixed, expected_pid=4104),
            "inventory refresh failed",
            "stale success hid the current PID's failed inventory",
        )

        dead = temp / "dead-app.log"
        dead.write_text("", encoding="utf-8")
        expect_failure(
            lambda: run_wait(dead, expected_pid=4105, identity_reader=lambda _pid: None),
            "exited or became unobservable",
            "dead app was allowed to time out or pass readiness",
        )

        zero_loaded = temp / "zero-loaded-completion.log"
        zero_loaded.write_text(unified_line(4106, "completed", 0, 1), encoding="utf-8")
        expect_failure(
            lambda: run_wait(zero_loaded, expected_pid=4106),
            "without a loaded source",
            "completed marker with no loaded source passed readiness",
        )

        missing_source_evidence = temp / "missing-source-evidence.log"
        missing_source_evidence.write_text(
            unified_line(4150, "completed", 1, 1, sources=()),
            encoding="utf-8",
        )
        expect_failure(
            lambda: run_wait(missing_source_evidence, expected_pid=4150),
            "0 source fingerprints for 1 loaded sources",
            "loaded source without identity evidence passed readiness",
        )

        duplicate_fingerprint = fixture_source_fingerprint("duplicate")
        duplicate_sources = temp / "duplicate-sources.log"
        duplicate_sources.write_text(
            unified_line(
                4151,
                "completed",
                2,
                2,
                sources=(duplicate_fingerprint, duplicate_fingerprint),
            ),
            encoding="utf-8",
        )
        expect_failure(
            lambda: run_wait(duplicate_sources, expected_pid=4151),
            "repeats a source fingerprint",
            "duplicate loaded-source evidence passed readiness",
        )

        overlap = temp / "loaded-disabled-overlap.log"
        overlap.write_text(
            unified_line(
                4152,
                "completed",
                1,
                1,
                sources=(duplicate_fingerprint,),
                disabled=(duplicate_fingerprint,),
            ),
            encoding="utf-8",
        )
        expect_failure(
            lambda: run_wait(overlap, expected_pid=4152),
            "loaded and disabled",
            "overlapping loaded/disabled source evidence passed readiness",
        )

        duplicate_disabled = temp / "duplicate-disabled-sources.log"
        duplicate_disabled.write_text(
            unified_line(
                4156,
                "completed",
                1,
                1,
                disabled=(duplicate_fingerprint, duplicate_fingerprint),
            ),
            encoding="utf-8",
        )
        expect_failure(
            lambda: run_wait(duplicate_disabled, expected_pid=4156),
            "repeats a disabled source fingerprint",
            "duplicate disabled-source evidence passed readiness",
        )

        malformed = temp / "malformed-source-evidence.log"
        malformed.write_text(
            unified_line(4153, "completed", 1, 1).replace(
                fixture_source_fingerprint("source-0"),
                "A" * 64,
            ),
            encoding="utf-8",
        )
        expect_failure(
            lambda: run_wait(malformed, expected_pid=4153),
            "timed out",
            "malformed source fingerprint satisfied the exact marker",
        )

        try:
            verifier.normalize_expected_source_fingerprint("a" * 63)
        except ValueError as error:
            check("64 lowercase hex" in str(error), "invalid expected-source diagnostic was unclear")
        else:
            raise AssertionError("short expected source fingerprint was accepted")

        hidden_managed_servers = temp / "hidden-managed-servers.log"
        hidden_managed_servers.write_text(
            unified_line(4154, "completed", 1, 1, managed=3, visible=0),
            encoding="utf-8",
        )
        expect_failure(
            lambda: run_wait(
                hidden_managed_servers,
                expected_pid=4154,
                require_unfiltered_servers=True,
            ),
            "rendered 0 of 3 managed servers",
            "clean launch hid managed servers but passed readiness",
        )
        check(
            run_wait(hidden_managed_servers, expected_pid=4154).visible_servers == 0,
            "intentional runtime filtering was rejected outside the clean-launch gate",
        )

        # False-positive control: per-source preflight evidence counts raw
        # observations, while managed/visible counts describe logical Board
        # rows. Two coordinators observing the same repository service must not
        # be rejected merely because their two raw rows collapse to one.
        duplicate_observation_fingerprints = (
            fixture_source_fingerprint("duplicate-observer-a"),
            fixture_source_fingerprint("duplicate-observer-b"),
        )
        duplicate_observation_counts = tuple(
            (fingerprint, 1) for fingerprint in duplicate_observation_fingerprints
        )
        collapsed_logical_server = temp / "collapsed-logical-server.log"
        collapsed_logical_server.write_text(
            unified_line(
                4160,
                "completed",
                2,
                2,
                sources=duplicate_observation_fingerprints,
                server_counts=duplicate_observation_counts,
                managed=1,
                visible=1,
                repositories=1,
            ),
            encoding="utf-8",
        )
        collapsed_ready = run_wait(
            collapsed_logical_server,
            expected_pid=4160,
            expected_source_inventory=verifier.format_expected_source_inventory(
                duplicate_observation_counts
            ),
            require_unfiltered_servers=True,
        )
        check(
            collapsed_ready.server_counts == duplicate_observation_counts
            and collapsed_ready.managed_servers == 1
            and collapsed_ready.visible_servers == 1,
            "logical source deduplication caused a false launch-readiness failure",
        )

        impossible_server_counts = temp / "impossible-server-counts.log"
        impossible_server_counts.write_text(
            unified_line(4155, "completed", 1, 1, managed=0, visible=1),
            encoding="utf-8",
        )
        expect_failure(
            lambda: run_wait(impossible_server_counts, expected_pid=4155),
            "more visible than managed",
            "impossible managed/visible server counts passed readiness",
        )

        # Must-catch the production-shaped regression: three coordinator
        # observations of one Nevod worktree rendered as three project rows.
        duplicated_repository_rows = temp / "duplicated-repository-rows.log"
        duplicated_repository_rows.write_text(
            unified_line(
                4157,
                "completed",
                3,
                3,
                server_counts=tuple(
                    (fixture_source_fingerprint(f"source-{index}"), count)
                    for index, count in enumerate((0, 16, 3))
                ),
                managed=19,
                visible=19,
                repositories=1,
                repository_groups=3,
            ),
            encoding="utf-8",
        )
        expect_failure(
            lambda: run_wait(duplicated_repository_rows, expected_pid=4157),
            "3 repository groups for 1 canonical repositories",
            "one canonical repository rendered three times but passed readiness",
        )

        # False-positive control: one explicit unassigned bucket may coexist
        # with repository groups without becoming another project.
        one_unassigned_group = temp / "one-unassigned-group.log"
        one_unassigned_group.write_text(
            unified_line(
                4158,
                "completed",
                2,
                2,
                server_counts=tuple(
                    (fixture_source_fingerprint(f"source-{index}"), 2)
                    for index in range(2)
                ),
                managed=4,
                visible=4,
                repositories=2,
                repository_groups=2,
                unassigned_groups=1,
            ),
            encoding="utf-8",
        )
        one_unassigned_ready = run_wait(one_unassigned_group, expected_pid=4158)
        check(
            one_unassigned_ready.repositories == 2
            and one_unassigned_ready.repository_groups == 2
            and one_unassigned_ready.unassigned_groups == 1,
            "one intentional unassigned-resources bucket caused a false readiness failure",
        )

        duplicate_unassigned_groups = temp / "duplicate-unassigned-groups.log"
        duplicate_unassigned_groups.write_text(
            unified_line(
                4159,
                "completed",
                2,
                2,
                repositories=1,
                repository_groups=1,
                unassigned_groups=2,
            ),
            encoding="utf-8",
        )
        expect_failure(
            lambda: run_wait(duplicate_unassigned_groups, expected_pid=4159),
            "2 unassigned resource groups; expected at most one",
            "multiple unassigned pseudo-project groups passed readiness",
        )

        near_match = temp / "near-match.log"
        near_match.write_text(
            unified_line(4107, "completed", 1, 1).rstrip("\n") + " debug-copy\n",
            encoding="utf-8",
        )
        expect_failure(
            lambda: run_wait(near_match, expected_pid=4107),
            "timed out",
            "non-exact telemetry text satisfied launch readiness",
        )

        # Intentional partial-source state: one usable coordinator is enough for
        # the Board to operate even while another source is unavailable.
        partial_sources = temp / "partial-sources.log"
        partial_sources.write_text(
            unified_line(
                4108,
                "completed",
                1,
                2,
                sources=(canonical_fingerprint,),
            ),
            encoding="utf-8",
        )
        partial_ready = run_wait(
            partial_sources,
            expected_pid=4108,
            expected_source_fingerprint=canonical_fingerprint,
        )
        check(
            partial_ready.loaded == 1
            and partial_ready.total == 2
            and partial_ready.health == "degraded"
            and partial_ready.attention_items == 1
            and partial_ready.resolution_targets == 1,
            "one loaded source out of two was incorrectly rejected",
        )

        # The production surface tails an initially empty log. Exercise a stale
        # line and a current marker split across separate writes.
        incremental = temp / "incremental.log"
        incremental.write_text("", encoding="utf-8")
        current_incremental_line = unified_line(4109, "completed", 1, 2)
        split_at = current_incremental_line.index("disabled=") + len("disabled=") + 7
        chunks = [
            unified_line(3999, "completed", 1, 1)
            + current_incremental_line[:split_at],
            current_incremental_line[split_at:],
        ]

        def append_incremental(_now: float) -> None:
            if chunks:
                with incremental.open("a", encoding="utf-8") as stream:
                    stream.write(chunks.pop(0))

        incremental_timeline = FakeTimeline(on_sleep=append_incremental)
        incremental_ready = run_wait(
            incremental,
            expected_pid=4109,
            timeline=incremental_timeline,
        )
        check(
            incremental_ready.loaded == 1 and incremental_ready.total == 2,
            "incrementally split readiness marker was not detected",
        )

        # Must-catch: the exact app dies after logging success but before the
        # sustained-health window completes.
        post_marker = temp / "post-marker-death.log"
        post_marker.write_text(unified_line(4110, "completed", 1, 1), encoding="utf-8")
        post_timeline = FakeTimeline()
        post_identity = verifier.ProcessIdentity(
            pid=4110,
            executable="/fixture/DevOpsBoard",
            start="fixture-start",
        )
        expect_failure(
            lambda: run_wait(
                post_marker,
                expected_pid=4110,
                timeline=post_timeline,
                identity_reader=lambda _pid: post_identity if post_timeline.now < 0.05 else None,
            ),
            "during launch stabilization",
            "app death immediately after the marker passed readiness",
        )

        # Must-catch: the capture dies while the app remains alive.
        capture_died = temp / "capture-died.log"
        capture_died.write_text("", encoding="utf-8")
        capture_timeline = FakeTimeline()
        expect_failure(
            lambda: run_wait(
                capture_died,
                expected_pid=4111,
                timeline=capture_timeline,
                capture_pid=9001,
                is_alive=lambda pid: pid != 9001 or capture_timeline.now < 0.05,
            ),
            "unified-log capture exited",
            "dead log capture was allowed to time out or pass",
        )

        # A delayed marker carrying the same numeric PID must still fail when
        # the process start identity belongs to a replacement process.
        reused_pid = temp / "reused-pid.log"
        reused_pid.write_text(unified_line(4112, "completed", 1, 1), encoding="utf-8")
        replacement = verifier.ProcessIdentity(
            pid=4112,
            executable="/fixture/DevOpsBoard",
            start="replacement-start",
        )
        expect_failure(
            lambda: run_wait(
                reused_pid,
                expected_pid=4112,
                identity_reader=lambda _pid: replacement,
            ),
            "changed identity",
            "same-PID replacement satisfied stale readiness telemetry",
        )

        wrong_executable = temp / "wrong-executable.log"
        wrong_executable.write_text(unified_line(4114, "completed", 1, 1), encoding="utf-8")
        foreign_binary = verifier.ProcessIdentity(
            pid=4114,
            executable="/fixture/NotDevOpsBoard",
            start="fixture-start",
        )
        expect_failure(
            lambda: run_wait(
                wrong_executable,
                expected_pid=4114,
                identity_reader=lambda _pid: foreign_binary,
            ),
            "changed identity",
            "same-PID foreign executable satisfied readiness telemetry",
        )

        # Exact-identity cleanup uses TERM first and stops without signaling a
        # replacement identity. A stubborn exact process escalates to KILL.
        cleanup_identity = verifier.ProcessIdentity(
            pid=4113,
            executable="/fixture/DevOpsBoard",
            start="cleanup-start",
        )
        cleanup_timeline = FakeTimeline()
        cleanup_signals: list[int] = []
        terminated = verifier.terminate_exact_process(
            cleanup_identity,
            grace=0.1,
            poll_interval=0.05,
            identity_reader=lambda _pid: cleanup_identity if cleanup_timeline.now < 0.05 else None,
            send_signal=lambda _pid, sent: cleanup_signals.append(sent),
            monotonic=cleanup_timeline.monotonic,
            sleep=cleanup_timeline.sleep,
        )
        check(terminated, "exact cleanup did not report termination")
        check(cleanup_signals == [signal.SIGTERM], f"cooperative cleanup signals were wrong: {cleanup_signals}")

        replacement_signals: list[int] = []
        replacement_identity = verifier.ProcessIdentity(
            pid=cleanup_identity.pid,
            executable=cleanup_identity.executable,
            start="new-process-start",
        )
        check(
            not verifier.terminate_exact_process(
                cleanup_identity,
                grace=0.1,
                identity_reader=lambda _pid: replacement_identity,
                send_signal=lambda _pid, sent: replacement_signals.append(sent),
            ),
            "cleanup claimed to terminate a replacement identity",
        )
        check(not replacement_signals, "cleanup signaled a replacement process")

        stubborn_timeline = FakeTimeline()
        stubborn_signals: list[int] = []
        expect_failure(
            lambda: verifier.terminate_exact_process(
                cleanup_identity,
                grace=0.1,
                poll_interval=0.05,
                identity_reader=lambda _pid: cleanup_identity,
                send_signal=lambda _pid, sent: stubborn_signals.append(sent),
                monotonic=stubborn_timeline.monotonic,
                sleep=stubborn_timeline.sleep,
            ),
            "retained its exact identity after SIGKILL",
            "stubborn process cleanup falsely reported success",
        )
        check(
            stubborn_signals == [signal.SIGTERM, signal.SIGKILL],
            f"stubborn cleanup did not use bounded TERM then KILL: {stubborn_signals}",
        )

        check_shell_behavior_harness(temp)

    print("DevOps Board launch-readiness self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
