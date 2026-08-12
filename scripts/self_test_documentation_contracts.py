#!/usr/bin/env python3
"""Verify copyable, repository-owned agent documentation contracts."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
ROOT_README = ROOT / "README.md"
RUNTIME_API = (
    ROOT
    / "skills"
    / "codex-dev-coordinator"
    / "references"
    / "runtime-api.md"
)
COORDINATOR_SKILL = ROOT / "skills" / "codex-dev-coordinator" / "SKILL.md"
AGENT_CLIENT = (
    ROOT
    / "skills"
    / "codex-dev-coordinator"
    / "references"
    / "agent-client.md"
)
OPENAI_AGENT = (
    ROOT
    / "skills"
    / "codex-dev-coordinator"
    / "agents"
    / "openai.yaml"
)
REPOSITORY_AGENTS = ROOT / "AGENTS.md"
SKILL_README = ROOT / "skills" / "codex-dev-coordinator" / "README.md"
TEST_ARCHITECTURE = ROOT / "docs" / "architecture" / "universal-test-harness.md"
POSTGRES_SKILL = ROOT / "skills" / "postgres-docker-backup" / "SKILL.md"


def section(markdown: str, heading: str) -> str:
    marker = f"## {heading}"
    start = markdown.find(marker)
    if start < 0:
        raise AssertionError(f"{heading!r} section is missing")
    end = markdown.find("\n## ", start + len(marker))
    return markdown[start:] if end < 0 else markdown[start:end]


def test_runtime_api_operator_links_resolve() -> None:
    operator_help = section(
        RUNTIME_API.read_text(encoding="utf-8"),
        "Lower-level and operator interfaces",
    )
    links = {
        label: target
        for label, target in re.findall(
            r"(?<!!)\[([^\]]+)\]\(([^)]+)\)",
            operator_help,
        )
    }
    required_labels = (
        "the coordinator skill README",
        "Console operations documentation",
    )
    for label in required_labels:
        target = links.get(label)
        if target is None:
            raise AssertionError(f"operator help omits the {label!r} link")
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or not parsed.path:
            raise AssertionError(
                f"operator help link {label!r} must be repository-relative: {target}"
            )
        resolved = (RUNTIME_API.parent / unquote(parsed.path)).resolve()
        try:
            resolved.relative_to(ROOT.resolve())
        except ValueError as error:
            raise AssertionError(
                f"operator help link {label!r} escapes the repository: {target}"
            ) from error
        if not resolved.is_file():
            raise AssertionError(
                f"operator help link {label!r} does not resolve: "
                f"{target} -> {resolved}"
            )


def broker_routing_snippet() -> str:
    routing = section(
        POSTGRES_SKILL.read_text(encoding="utf-8"),
        "Multi-user Broker Routing",
    )
    match = re.search(r"```bash\n(.*?)\n```", routing, re.DOTALL)
    if match is None:
        raise AssertionError("broker-routing bash example is missing")
    return match.group(1)


def test_broker_routing_resolves_skill_tool_before_project_cd() -> None:
    snippet = broker_routing_snippet()
    with tempfile.TemporaryDirectory(
        prefix="devcoordinator-doc-contract-"
    ) as temporary:
        temporary_root = Path(temporary)
        unrelated_project = temporary_root / "unrelated-project"
        fake_bin = temporary_root / "bin"
        record = temporary_root / "invocation.txt"
        unrelated_project.mkdir()
        fake_bin.mkdir()
        python_shim = fake_bin / "python3"
        python_shim.write_text(
            """#!/bin/sh
set -eu
if [ "$PWD" != "$PROJECT_ROOT" ]; then
  echo "broker route did not run from PROJECT_ROOT: $PWD" >&2
  exit 71
fi
if [ "$#" -ne 2 ] || [ "$2" != "route" ]; then
  echo "unexpected broker route argv: $*" >&2
  exit 72
fi
case "$1" in
  /*) ;;
  *)
    echo "broker tool path is not absolute: $1" >&2
    exit 73
    ;;
esac
if [ ! -x "$1" ]; then
  echo "broker tool path is not an existing executable: $1" >&2
  exit 74
fi
printf '%s\\n%s\\n%s\\n' "$PWD" "$1" "$2" > "$DOC_CONTRACT_RECORD"
""",
            encoding="utf-8",
        )
        python_shim.chmod(0o755)
        environment = os.environ.copy()
        environment.update(
            {
                "DOC_CONTRACT_RECORD": str(record),
                "PATH": f"{fake_bin}{os.pathsep}{environment['PATH']}",
                "PROJECT_ROOT": str(unrelated_project),
            }
        )
        completed = subprocess.run(
            [
                "bash",
                "--noprofile",
                "--norc",
                "-eu",
                "-o",
                "pipefail",
                "-c",
                snippet,
            ],
            cwd=POSTGRES_SKILL.parent,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise AssertionError(
                "broker-routing example is not copyable from the skill into "
                f"an unrelated project: {detail}"
            )
        recorded_cwd, tool, action = record.read_text(
            encoding="utf-8"
        ).splitlines()
        expected_tool = (
            POSTGRES_SKILL.parent / "scripts" / "postgres_docker_backup.py"
        ).resolve()
        if recorded_cwd != str(unrelated_project):
            raise AssertionError(
                f"broker route ran from {recorded_cwd}, not {unrelated_project}"
            )
        if Path(tool) != expected_tool:
            raise AssertionError(
                f"broker route selected {tool}, not canonical {expected_tool}"
            )
        if action != "route":
            raise AssertionError(f"broker route selected unexpected action {action}")


def test_first_use_runtime_journey_is_copyable_and_explanatory() -> None:
    skill = COORDINATOR_SKILL.read_text(encoding="utf-8")
    reference = AGENT_CLIENT.read_text(encoding="utf-8")
    normalized_skill = " ".join(skill.split())
    normalized_reference = " ".join(reference.split())
    required_skill_fragments = (
        "repository.state=unenrolled",
        "devcoordinator runtime serve prototype",
        "--cwd . --port 4173 --ttl-seconds 3600",
        "--kill-after-run false --launch-timeout-seconds 30 --",
        "npm run dev -- --host 0.0.0.0 --port 4173 --strictPort",
        "Do not ask an administrator",
        "coding sandbox",
        "`EACCES`, `EPERM`",
        "No Coordinator call occurred",
        "local fallback",
        "never an instruction to",
        "whether the broker was contacted",
        "whether mutation occurred",
        "broker_contacted=false",
        "mutation_performed=true",
        "devcoordinator runtime serve --help",
        "devcoordinator operation follow dc1:operation:",
    )
    missing = [
        item
        for item in required_skill_fragments
        if item not in skill and item not in normalized_skill
    ]
    if missing:
        raise AssertionError(
            "Coordinator skill omits first-use/runtime guidance: "
            + ", ".join(missing)
        )
    for field in (
        "broker_contacted",
        "mutation_performed",
        "retryability",
        "exact next command",
        "Direct host bind failed",
        "Invalid serve shape",
        "Local fallback is disabled",
        "devcoordinator runtime serve --help",
        "devcoordinator operation follow dc1:operation:",
    ):
        if field not in reference and field not in normalized_reference:
            raise AssertionError(
                f"agent-client failure contract omits {field!r}"
            )


def _require_fragments(
    *,
    label: str,
    text: str,
    fragments: tuple[str, ...],
) -> None:
    normalized = " ".join(text.split())
    missing = [
        fragment
        for fragment in fragments
        if fragment not in text and fragment not in normalized
    ]
    if missing:
        raise AssertionError(f"{label} omits: " + ", ".join(missing))


def _require_local_links_resolve(*, source: Path, markdown: str) -> None:
    for label, target in re.findall(
        r"(?<!!)\[([^\]]+)\]\(([^)]+)\)",
        markdown,
    ):
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or not parsed.path:
            continue
        resolved = (source.parent / unquote(parsed.path)).resolve()
        try:
            resolved.relative_to(ROOT.resolve())
        except ValueError as error:
            raise AssertionError(
                f"{source} link {label!r} escapes the repository: {target}"
            ) from error
        if not resolved.is_file():
            raise AssertionError(
                f"{source} link {label!r} does not resolve: {target}"
            )


def test_local_test_scope_is_bounded_and_batched() -> None:
    skill = COORDINATOR_SKILL.read_text(encoding="utf-8")
    reference = AGENT_CLIENT.read_text(encoding="utf-8")
    agents = REPOSITORY_AGENTS.read_text(encoding="utf-8")
    root_readme = ROOT_README.read_text(encoding="utf-8")
    readme = SKILL_README.read_text(encoding="utf-8")
    metadata = OPENAI_AGENT.read_text(encoding="utf-8")
    architecture = TEST_ARCHITECTURE.read_text(encoding="utf-8")

    for label, text in (
        ("Coordinator skill", skill),
        ("agent-client reference", reference),
        ("repository agent instructions", agents),
        ("root README", root_readme),
        ("skill README", readme),
        ("OpenAI skill metadata", metadata),
        ("test architecture", architecture),
    ):
        _require_fragments(
            label=f"{label} local-test boundary",
            text=text,
            fragments=("20 cases", "10 seconds"),
        )

    _require_fragments(
        label="Coordinator skill governed-batch routing",
        text=skill,
        fragments=(
            "Unit-test isolation does not make a broad invocation locally eligible",
            "If either bound is unknown",
            "use one governed batch",
            "Do not recreate the selected batch",
            "at most 20 collected cases and at most 10 seconds",
            "Do not split a larger suite",
            "21 collected cases",
            "11-second execution allowance",
            "unknown case or runtime scope",
            "an unfiltered runner",
            "a thousand-case suite",
            "UIL-TESTING-011",
        ),
    )
    _require_fragments(
        label="agent-client governed-batch routing",
        text=reference,
        fragments=(
            "Local feedback versus governed batches",
            "Unit-test isolation alone is not proof of local eligibility",
            "If the collected-case count or runtime bound is unknown",
            "enqueue one governed batch",
            "must not split a larger suite",
        ),
    )
    _require_fragments(
        label="repository agent routing",
        text=agents,
        fragments=(
            "proven before launch",
            "one Coordinator test enqueue",
            "either bound is unknown or exceeded",
        ),
    )
    forbidden = (
        "isolated unit tests that do not touch a shared runtime",
        "repository-native isolated unit or static checks",
    )
    for phrase in forbidden:
        if phrase in skill or phrase in reference:
            raise AssertionError(
                "local-test guidance restored the unbounded isolation rule: "
                + phrase
            )


def test_bug_intake_and_advisory_fallback_are_explicit() -> None:
    complete_skill = COORDINATOR_SKILL.read_text(encoding="utf-8")
    complete_reference = AGENT_CLIENT.read_text(encoding="utf-8")
    skill = section(
        complete_skill,
        "Report Coordinator failures without blocking source work",
    )
    reference = section(
        complete_reference,
        "Independent failure intake and advisory test fallback",
    )
    skill_mcp = section(complete_skill, "Optional MCP surface")
    reference_mcp = section(complete_reference, "Optional MCP stdio")
    readme = ROOT_README.read_text(encoding="utf-8")
    agent_metadata = OPENAI_AGENT.read_text(encoding="utf-8")

    common_contract = (
        "devcoordinator-bug report",
        "--component",
        "--summary",
        "--expected",
        "--actual",
        "--step",
        "--command-arg=",
        "--call-id",
        "--operation-id",
        "--run-id",
        "--attempt-id",
        "devcoordinator bug report",
        "Do not auto-message another Codex task",
        "invalid caller argument",
        "before Coordinator contact",
        "direct sandbox",
        "caller misuse",
        "not automatically a Coordinator bug",
        "typed Coordinator tool or infrastructure",
        "devcoordinator-bug list --limit 20",
        "devcoordinator-bug close BUG_ID",
        "physically removes",
        "open",
        "local/advisory — non-governed; not Coordinator evidence",
        "handoff or release readiness",
        "governed",
        "host listeners",
        "Docker",
        "databases",
        "shared processes",
        "host mutation",
        "measured assertion",
        "project bug",
        "DC-2026-08-04-BUG-INTAKE-01",
        "security-assumptions.md",
        "UIL-DOCUMENTATION-002",
        "UIL-TESTING-006",
    )
    _require_fragments(
        label="Coordinator skill bug workflow",
        text=skill,
        fragments=common_contract,
    )
    _require_fragments(
        label="agent-client bug workflow",
        text=reference,
        fragments=common_contract
        + (
            "at least one ordered `step`",
            "using the equals form when `ARG` begins with `-`",
            "correlations are optional",
            "--local-fallback-status not_run|passed|failed|incomplete",
            "--local-test-command-arg=ARG",
            "--local-fallback-summary TEXT",
            "no repository enrollment, profile, broker, API, authority, testd, or call journal",
            "must be followed by a governed rerun after repair",
        ),
    )
    _require_fragments(
        label="root README bug workflow",
        text=readme,
        fragments=(
            "devcoordinator-bug report",
            "--component",
            "--summary",
            "--expected",
            "--actual",
            "--step",
            "--command-arg=",
            "devcoordinator-bug list --limit 20",
            "devcoordinator-bug close BUG_ID",
            "Do not auto-message",
            "physically removes",
            "local/advisory — non-governed; not Coordinator evidence",
            "handoff or release readiness",
            "host listeners",
            "Docker/Compose",
            "databases",
            "shared processes",
            "host mutation",
            "Ordinary measured assertion failures are project bugs",
            "DC-2026-08-04-BUG-INTAKE-01",
            "security-assumptions.md",
            "invalid caller arguments",
            "direct sandbox",
            "never contacted Coordinator",
            "caller misuse",
            "not automatically Coordinator bugs",
        ),
    )
    _require_fragments(
        label="OpenAI skill metadata",
        text=agent_metadata,
        fragments=(
            "devcoordinator-bug report",
            "local/advisory",
            "non-governed",
            "release evidence",
        ),
    )

    for label, text in (
        ("Coordinator skill", skill),
        ("agent-client reference", reference),
        ("root README", readme),
    ):
        if "devcoordinator-bug inspect" in text or "devcoordinator bug inspect" in text:
            raise AssertionError(f"{label} invents a non-existent inspect action")
    if skill.index("devcoordinator-bug report") > skill.index(
        "continue repository-native"
    ):
        raise AssertionError(
            "Coordinator skill must report the harness failure before local checks"
        )
    if skill.count("--step") < 2 or skill.count("--command-arg=") < 5:
        raise AssertionError(
            "Coordinator skill example lacks ordered steps or structured argv"
        )

    for label, mcp_section in (
        ("Coordinator skill MCP contract", skill_mcp),
        ("agent-client MCP contract", reference_mcp),
    ):
        _require_fragments(
            label=label,
            text=mcp_section,
            fragments=(
                "bug_report",
                "bug_list",
                "bug_close",
                "open",
                "physically removes",
                "repository context",
                "profiles",
            ),
        )

    _require_local_links_resolve(source=COORDINATOR_SKILL, markdown=skill)
    _require_local_links_resolve(source=AGENT_CLIENT, markdown=reference)


def main() -> int:
    tests = (
        test_runtime_api_operator_links_resolve,
        test_broker_routing_resolves_skill_tool_before_project_cd,
        test_first_use_runtime_journey_is_copyable_and_explanatory,
        test_local_test_scope_is_bounded_and_batched,
        test_bug_intake_and_advisory_fallback_are_explicit,
    )
    failures: list[str] = []
    for test in tests:
        try:
            test()
        except Exception as error:
            failures.append(f"{test.__name__}: {error}")
    if failures:
        print("documentation contract self-test failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print(f"documentation contract self-test passed ({len(tests)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
