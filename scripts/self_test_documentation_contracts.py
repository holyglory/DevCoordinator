#!/usr/bin/env python3
"""Verify copyable, split, repository-owned agent documentation contracts."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
ROOT_README = ROOT / "README.md"
REPOSITORY_AGENTS = ROOT / "AGENTS.md"
RUNTIME_ROOT = ROOT / "skills" / "codex-dev-coordinator"
RUNTIME_SKILL = RUNTIME_ROOT / "SKILL.md"
RUNTIME_CLIENT = RUNTIME_ROOT / "references" / "agent-client.md"
RUNTIME_API = RUNTIME_ROOT / "references" / "runtime-api.md"
ADMIN_OPERATIONS = RUNTIME_ROOT / "references" / "admin-operations.md"
RUNTIME_METADATA = RUNTIME_ROOT / "agents" / "openai.yaml"
TEST_ROOT = ROOT / "skills" / "codex-governed-tests"
TEST_SKILL = TEST_ROOT / "SKILL.md"
TEST_CLIENT = TEST_ROOT / "references" / "governed-test-client.md"
TEST_MANIFEST = TEST_ROOT / "references" / "manifest-and-evidence.md"
TEST_FAILURE = TEST_ROOT / "references" / "failure-intake.md"
TEST_METADATA = TEST_ROOT / "agents" / "openai.yaml"
TEST_ARCHITECTURE = ROOT / "docs" / "architecture" / "universal-test-harness.md"
PRODUCTION_ACCEPTANCE = (
    ROOT / "apps" / "DevOpsConsole" / "Tools" / "production-console-acceptance.mjs"
)
POSTGRES_SKILL = ROOT / "skills" / "postgres-docker-backup" / "SKILL.md"
BROKER_CLI = (
    RUNTIME_ROOT / "scripts" / "devcoordinator" / "broker_cli.py"
)
FIRST_USE_TRUST_DECISION = (
    ROOT / "DecisionDetails" / "DC-2026-08-04-FIRST-USE-TRUST-01.md"
)


def section(markdown: str, heading: str) -> str:
    marker = f"## {heading}"
    start = markdown.find(marker)
    if start < 0:
        raise AssertionError(f"{heading!r} section is missing")
    end = markdown.find("\n## ", start + len(marker))
    return markdown[start:] if end < 0 else markdown[start:end]


def require_fragments(*, label: str, text: str, fragments: tuple[str, ...]) -> None:
    normalized = " ".join(text.split())
    missing = [
        fragment
        for fragment in fragments
        if fragment not in text and fragment not in normalized
    ]
    if missing:
        raise AssertionError(f"{label} omits: " + ", ".join(missing))


def local_markdown_links(source: Path, markdown: str) -> list[Path]:
    links: list[Path] = []
    for _label, target in re.findall(r"(?<!!)\[([^\]]+)\]\(([^)]+)\)", markdown):
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or not parsed.path:
            continue
        resolved = (source.parent / unquote(parsed.path)).resolve()
        try:
            resolved.relative_to(ROOT.resolve())
        except ValueError as error:
            raise AssertionError(f"{source} link escapes the repository: {target}") from error
        if not resolved.is_file():
            raise AssertionError(f"{source} link does not resolve: {target}")
        links.append(resolved)
    return links


def test_split_skills_have_distinct_triggers_and_generated_metadata() -> None:
    runtime = RUNTIME_SKILL.read_text(encoding="utf-8")
    governed = TEST_SKILL.read_text(encoding="utf-8")
    runtime_frontmatter = runtime.split("---", 2)[1]
    governed_frontmatter = governed.split("---", 2)[1]
    require_fragments(
        label="runtime trigger",
        text=runtime_frontmatter,
        fragments=(
            "host-visible development runtimes",
            "coding sandbox cannot bind a development port",
            "first-use runtime adoption",
            "Do not use for",
            "governed test execution",
        ),
    )
    if "20 cases" in runtime_frontmatter or "10 seconds" in runtime_frontmatter:
        raise AssertionError("runtime metadata still competes for governed-test routing")
    require_fragments(
        label="governed-test trigger",
        text=governed_frontmatter,
        fragments=(
            "more than 20 cases",
            "longer than 10 seconds",
            "cannot prove both bounds",
            "shared listener",
            "durable evidence",
            "artifact retrieval or export",
        ),
    )
    for name, metadata in (
        ("codex-dev-coordinator", RUNTIME_METADATA),
        ("codex-governed-tests", TEST_METADATA),
    ):
        text = metadata.read_text(encoding="utf-8")
        require_fragments(
            label=f"{name} metadata",
            text=text,
            fragments=("display_name:", "short_description:", f"${name}"),
        )
    if (TEST_ROOT / "scripts").exists():
        raise AssertionError("governed-tests must remain documentation-only")


def test_every_skill_reference_is_direct_and_resolves() -> None:
    for root, skill in ((RUNTIME_ROOT, RUNTIME_SKILL), (TEST_ROOT, TEST_SKILL)):
        markdown = skill.read_text(encoding="utf-8")
        linked = set(local_markdown_links(skill, markdown))
        references = {
            path.resolve()
            for path in (root / "references").glob("*.md")
            if path.is_file()
        }
        missing = sorted(str(path.relative_to(ROOT)) for path in references - linked)
        if missing:
            raise AssertionError(
                f"{skill.relative_to(ROOT)} does not directly link references: "
                + ", ".join(missing)
            )
        for reference in references:
            text = reference.read_text(encoding="utf-8")
            if len(text.splitlines()) > 100 and "## Contents" not in text:
                raise AssertionError(f"long reference lacks contents: {reference}")
            local_markdown_links(reference, text)


def test_first_use_runtime_journey_is_copyable_and_explanatory() -> None:
    skill = RUNTIME_SKILL.read_text(encoding="utf-8")
    client = RUNTIME_CLIENT.read_text(encoding="utf-8")
    require_fragments(
        label="runtime first-use skill",
        text=skill,
        fragments=(
            "repository.state=unenrolled",
            "devcoordinator runtime serve prototype",
            "--cwd . --port 4173 --ttl-seconds 3600",
            "--kill-after-run false --launch-timeout-seconds 30 --",
            "npm run dev -- --host 0.0.0.0 --port 4173 --strictPort",
            "`EACCES`, `EPERM`",
            "No Coordinator call occurred",
            "Local fallback",
            "broker_contacted=false",
            "mutation_performed=false",
            "devcoordinator runtime serve --help",
            "devcoordinator operation follow dc1:operation:",
        ),
    )
    require_fragments(
        label="runtime first-use reference",
        text=client,
        fragments=(
            "First-use diagnosis",
            "broker_contacted=false",
            "mutation_performed=true",
            "Local fallback is disabled",
            "operation follow",
        ),
    )


def test_compose_approval_documentation_is_precise() -> None:
    administration = section(
        ADMIN_OPERATIONS.read_text(encoding="utf-8"),
        "Compose host-access approval",
    )
    broker_cli = BROKER_CLI.read_text(encoding="utf-8")
    prior_decision = FIRST_USE_TRUST_DECISION.read_text(encoding="utf-8")
    require_fragments(
        label="Compose approval administration",
        text=administration,
        fragments=(
            "`host_bind_mount`",
            "`added_capabilities`",
            "complete effective-model risk evidence",
            "`volume_driver_bind`",
            "still-gated category",
            "non-loopback, wildcard, or malformed host publication",
            "devices or GPUs",
            "privileged mode",
            "host namespaces",
            "Docker-socket access",
            "unconfined security",
            "external containers, networks, or volumes",
            "devcoordinator-compose-host-access",
            "devcoordinator-authority-repository-repair",
            "Any changed or added approval-required risk",
            "adding only `host_bind_mount` or `added_capabilities` does not",
        ),
    )
    require_fragments(
        label="Compose approval CLI help",
        text=broker_cli,
        fragments=(
            "still-gated host access",
            "volume-driver binds",
            "Service-level bind mounts and cap_add",
            "do not require this flag",
            "risk set that remains approval-required",
        ),
    )
    require_fragments(
        label="first-use Compose approval supersession",
        text=prior_decision,
        fragments=(
            "DC-2026-08-22-COMPOSE-DECLARED-HOST-CAPABILITIES-01",
            "`host_bind_mount`",
            "`added_capabilities`",
            "`volume_driver_bind`",
            "every other approval boundary in this record remain unchanged",
            "historical for those two exempt categories",
        ),
    )
    for label, text in (
        ("administration", administration),
        ("broker CLI", broker_cli),
    ):
        if "bind mounts, devices, host namespaces, added capabilities" in text:
            raise AssertionError(
                f"{label} still says service bind mounts and cap_add require approval"
            )


def test_governed_routing_surface_and_evidence_are_complete() -> None:
    skill = TEST_SKILL.read_text(encoding="utf-8")
    client = TEST_CLIENT.read_text(encoding="utf-8")
    manifest = TEST_MANIFEST.read_text(encoding="utf-8")
    agents = REPOSITORY_AGENTS.read_text(encoding="utf-8")
    readme = ROOT_README.read_text(encoding="utf-8")
    architecture = TEST_ARCHITECTURE.read_text(encoding="utf-8")
    for label, text in (
        ("governed skill", skill),
        ("repository instructions", agents),
        ("root README", readme),
        ("test architecture", architecture),
    ):
        require_fragments(
            label=f"{label} local boundary",
            text=text,
            fragments=("20 cases", "10 seconds"),
        )
    require_fragments(
        label="governed routing",
        text=skill,
        fragments=(
            "Unit-test isolation alone does not prove eligibility",
            "21 cases",
            "11-second allowance",
            "unknown scope",
            "unfiltered runner",
            "thousand-case suite",
            "Do not silently run the broad suite",
            "devcoordinator test enqueue --intent change",
            "devcoordinator test submit dc1:plan:PLAN_ID",
            "submission_performed=false",
            "queue-status",
            "failures",
            "cases",
            "artifact-export",
            "cancel",
            "retry",
            "no standalone stable `test run`",
            "policy, catalog, stats, and wait",
            "one execution slot per",
            "no automatic or in-run retry",
        ),
    )
    require_fragments(
        label="enqueue/follow contract",
        text=client,
        fragments=(
            "prompt acknowledgement",
            "same-schema authority or testd replacement",
            "final response margin",
            "last valid observation",
            "never resubmits",
            "largest ordered non-empty prefix",
            "`next_cursor`",
            "same-schema release digest change",
            "--project",
        ),
    )
    require_fragments(
        label="manifest/evidence contract",
        text=manifest,
        fragments=(
            "Manifest schema 4",
            "complete normalized target execution specification",
            "LoadCredential=",
            "SQLite state handle",
            "one execution slot",
            "result-package.tar",
            "no semantic result-chunk protocol",
            "one exact failure record",
            "bounded UTF-8 tail",
            "mode-0600",
            "Installed test-access acceptance",
        ),
    )
    require_fragments(
        label="current test architecture",
        text=architecture,
        fragments=(
            "one execution slot per selected target",
            "result-package.tar",
            "Restart never renews a lease",
            "systemd cgroup/TTL cleanup",
            "Cgroup isolation",
            "per-run resource quotas are not",
            "exact repository ID and generation",
            "path escape",
            "idempotent replay",
            "recorded actual non-root",
            "LoadCredential=",
            "fixed 8 KiB ceiling",
        ),
    )
    for label, text in (
        ("governed skill", skill),
        ("governed client", client),
        ("manifest/evidence", manifest),
        ("test architecture", architecture),
    ):
        for retired in (
            "--spool",
            "`max_attempts` and reviewed `retry_on`",
            "lease_expired_before_launch",
            "publishes atomic ordered result chunks",
            "same-schema active-attempt recovery",
        ):
            if retired in text:
                raise AssertionError(f"{label} still documents retired contract: {retired}")


def test_failure_intake_fallback_task_routing_and_public_audit_are_explicit() -> None:
    failure = TEST_FAILURE.read_text(encoding="utf-8")
    skill = TEST_SKILL.read_text(encoding="utf-8")
    acceptance = PRODUCTION_ACCEPTANCE.read_text(encoding="utf-8")
    require_fragments(
        label="failure intake",
        text=failure,
        fragments=(
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
            "invalid caller argument",
            "direct sandbox bind",
            "local/advisory — non-governed; not Coordinator evidence",
            "handoff/release readiness",
            "Do not auto-message",
            "zero or multiple tasks",
            "devcoordinator-bug list --limit 20",
            "devcoordinator-bug close BUG_ID",
            "physically removes",
            "production `/api/bugs`",
            "rendered `#/bugs`",
        ),
    )
    if skill.index("file one structured report") > skill.index(
        "local development may continue"
    ):
        raise AssertionError("governed skill permits fallback before bug intake")
    require_fragments(
        label="production bug audit",
        text=acceptance,
        fragments=(
            "fetch('/api/bugs'",
            "cache: 'no-store'",
            "open bug registry parity",
            "rendered Bugs page/API count mismatch",
        ),
    )


def broker_routing_snippet() -> str:
    routing = section(
        POSTGRES_SKILL.read_text(encoding="utf-8"), "Multi-user Broker Routing"
    )
    match = re.search(r"```bash\n(.*?)\n```", routing, re.DOTALL)
    if match is None:
        raise AssertionError("broker-routing bash example is missing")
    return match.group(1)


def test_broker_routing_example_remains_copyable() -> None:
    snippet = broker_routing_snippet()
    with tempfile.TemporaryDirectory(prefix="devcoordinator-doc-contract-") as temporary:
        temporary_root = Path(temporary)
        project = temporary_root / "unrelated project"
        fake_bin = temporary_root / "bin"
        record = temporary_root / "invocation.txt"
        project.mkdir()
        fake_bin.mkdir()
        shim = fake_bin / "python3"
        shim.write_text(
            "#!/bin/sh\nset -eu\n"
            "[ \"$PWD\" = \"$PROJECT_ROOT\" ] || exit 71\n"
            "[ \"$#\" -eq 2 ] && [ \"$2\" = route ] || exit 72\n"
            "case \"$1\" in /*) ;; *) exit 73 ;; esac\n"
            "[ -x \"$1\" ] || exit 74\n"
            "printf '%s\\n%s\\n' \"$PWD\" \"$1\" > \"$DOC_CONTRACT_RECORD\"\n",
            encoding="utf-8",
        )
        shim.chmod(0o755)
        environment = dict(os.environ)
        environment.update(
            {
                "DOC_CONTRACT_RECORD": str(record),
                "PATH": f"{fake_bin}{os.pathsep}{environment['PATH']}",
                "PROJECT_ROOT": str(project),
            }
        )
        completed = subprocess.run(
            ["bash", "--noprofile", "--norc", "-eu", "-o", "pipefail", "-c", snippet],
            cwd=POSTGRES_SKILL.parent,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode != 0:
            raise AssertionError(
                "broker-routing example is not copyable: "
                + (completed.stderr.strip() or completed.stdout.strip())
            )
        cwd, tool = record.read_text(encoding="utf-8").splitlines()
        expected = (POSTGRES_SKILL.parent / "scripts" / "postgres_docker_backup.py").resolve()
        if cwd != str(project) or Path(tool) != expected:
            raise AssertionError("broker-routing example selected the wrong cwd or tool")


def main() -> int:
    tests = (
        test_split_skills_have_distinct_triggers_and_generated_metadata,
        test_every_skill_reference_is_direct_and_resolves,
        test_first_use_runtime_journey_is_copyable_and_explanatory,
        test_compose_approval_documentation_is_precise,
        test_governed_routing_surface_and_evidence_are_complete,
        test_failure_intake_fallback_task_routing_and_public_audit_are_explicit,
        test_broker_routing_example_remains_copyable,
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
