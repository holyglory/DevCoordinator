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
) -> str:
    if sources is None:
        sources = tuple(fixture_source_fingerprint(f"source-{index}") for index in range(loaded))
    visible = managed if visible is None else visible
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
        f"managed={managed} visible={visible}\n"
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
    check(verifier.process_state_is_alive("Ss+"), "ordinary sleeping process state was rejected")
    check(not verifier.process_state_is_alive("Z+"), "zombie process state was treated as alive")
    check(not verifier.process_state_is_alive("  "), "empty process state was treated as alive")
    with tempfile.TemporaryDirectory(prefix="devops-board-launch-readiness-") as raw_temp:
        temp = Path(raw_temp)

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
            verifier.expected_automatic_source_fingerprint(account_home=absent_home, environment={}) is None,
            "absent automatic source incorrectly became a launch requirement",
        )
        try:
            verifier.expected_automatic_source_fingerprint(
                account_home=account_home,
                environment={},
                entry_exists=lambda _path: (_ for _ in ()).throw(PermissionError("fixture denied")),
            )
        except PermissionError:
            # An injected observer is already outside the production
            # sanitizer; separately exercise that sanitizer below.
            pass
        else:
            raise AssertionError("unobservable automatic source was collapsed to absent")
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

        # Must-catch: all auto-discovery channels used by the product are
        # required, including two Parall-hosted Codex instances. Lexical aliases
        # of one physical source are deduplicated by canonical path.
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
            environment={"CODEX_AGENT_COORDINATOR_HOME": str(alias)},
        )
        check(
            discovered == multi_sources,
            f"multi-instance automatic discovery was incomplete or not canonical: {discovered!r}",
        )
        multi_fingerprints = tuple(sorted(verifier.source_fingerprint(path) for path in multi_sources))
        check(
            verifier.expected_automatic_source_fingerprints(
                account_home=multi_home,
                environment={"CODEX_AGENT_COORDINATOR_HOME": str(alias)},
            )
            == multi_fingerprints,
            "automatic source evidence did not cover both Codex instances and both account channels",
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
            count = json.loads((home / "state.json").read_text())["fixture_server_count"]
            print(json.dumps({"coordinator_home": str(home), "servers": [{}] * count}))
            """,
        )
        measured_inventory = verifier.collect_expected_source_inventory(
            coordinator_script=fake_coordinator,
            source_paths=multi_sources,
        )
        expected_count_by_fingerprint = {
            verifier.source_fingerprint(path): count
            for path, count in zip(multi_sources, source_counts)
        }
        check(
            dict(measured_inventory) == expected_count_by_fingerprint,
            "packaged-helper preflight did not bind each source to its real server count",
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

        multi_loaded_counts = tuple(
            sorted(
                (verifier.source_fingerprint(path), count)
                for path, count in zip(multi_sources, source_counts)
            )
        )
        all_instances = temp / "all-codex-instances.log"
        all_instances.write_text(
            unified_line(
                4095,
                "completed",
                4,
                4,
                sources=tuple(fingerprint for fingerprint, _count in multi_loaded_counts),
                server_counts=multi_loaded_counts,
                managed=sum(source_counts),
                visible=sum(source_counts),
            ),
            encoding="utf-8",
        )
        check(
            run_wait(
                all_instances,
                expected_pid=4095,
                expected_source_inventory=measured_inventory_argument,
                require_unfiltered_servers=True,
            ).loaded
            == 4,
            "two-instance source set did not pass source-bound readiness",
        )

        missing_instance = temp / "missing-codex-instance.log"
        present_counts = multi_loaded_counts[:-1]
        missing_instance.write_text(
            unified_line(
                4096,
                "completed",
                3,
                3,
                sources=tuple(fingerprint for fingerprint, _count in present_counts),
                server_counts=present_counts,
                managed=sum(count for _fingerprint, count in present_counts),
            ),
            encoding="utf-8",
        )
        expect_failure(
            lambda: run_wait(
                missing_instance,
                expected_pid=4096,
                expected_source_inventory=measured_inventory_argument,
            ),
            "1 automatic OS-account coordinator source(s)",
            "one missing Codex-instance source passed multi-source readiness",
        )

        disabled_fingerprint, _disabled_count = multi_loaded_counts[-1]
        intentionally_disabled_instance = temp / "disabled-codex-instance.log"
        intentionally_disabled_instance.write_text(
            unified_line(
                4097,
                "completed",
                3,
                3,
                sources=tuple(fingerprint for fingerprint, _count in present_counts),
                disabled=(disabled_fingerprint,),
                server_counts=present_counts,
                managed=sum(count for _fingerprint, count in present_counts),
            ),
            encoding="utf-8",
        )
        check(
            run_wait(
                intentionally_disabled_instance,
                expected_pid=4097,
                expected_source_inventory=measured_inventory_argument,
            ).loaded
            == 3,
            "explicitly disabled second-instance source caused a false readiness failure",
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
        # loaded source. The same unknown evidence is intentional when that
        # source is explicitly disabled and therefore not read by the Board.
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
        unknown_but_disabled = run_wait(
            explicitly_disabled,
            expected_pid=4092,
            expected_source_inventory=f"{canonical_fingerprint}:?",
        )
        check(
            unknown_but_disabled.loaded == 1,
            "an intentionally disabled unmeasured source caused a false readiness failure",
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
            partial_ready.loaded == 1 and partial_ready.total == 2,
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
