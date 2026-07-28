"""Administrator-approved, snapshot-bound Docker image publication.

The normal Dev Coordinator broker intentionally exposes no generic Docker build
operation.  A build can execute arbitrary Dockerfile instructions and therefore
must never be reachable through the untrusted client socket.  This module is
used only by the root-only ``broker publish-image`` administration command.

It turns one narrow runtime declaration into a root-owned source snapshot,
records the exact evidence that was built, and later accepts only that snapshot
for a sealed Compose rollout.  The caller may not provide Docker arguments,
paths, or a command string.
"""

from __future__ import annotations

from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import subprocess
import time
from typing import Any, Callable, Iterator, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import uuid

from .broker_host import (
    LocalBrokerHostMutations,
    _resolve_docker_executable,
    _sealed_compose_input_snapshots,
    render_compose_effective_model,
)
from .compose_contract import (
    bounded_compose_environment,
    require_effective_compose_model,
    require_sealable_compose_payload,
)


ARTIFACT_VERSION = 1
BUILD_TIMEOUT_SECONDS = 20 * 60
COMPOSE_TIMEOUT_SECONDS = 6 * 60
HEALTH_RESPONSE_LIMIT = 64 * 1024
BUILD_DIAGNOSTIC_LIMIT = 4 * 1024
MAX_CONTEXT_FILE_BYTES = 128 * 1024 * 1024
MAX_CONTEXT_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_CONTEXT_FILES = 20_000
MAX_CONTEXT_PATHS = 16
MAX_PLAN_AGE_SECONDS = 60 * 60

_IMAGE_REFERENCE = re.compile(
    r"[a-z0-9][a-z0-9._/-]{0,199}:[A-Za-z0-9][A-Za-z0-9._-]{0,127}"
)
_PUBLICATION_NAME = re.compile(r"[a-z][a-z0-9-]{0,62}")
_SERVICE_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}")
_PROJECT_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
_FINGERPRINT = re.compile(r"[a-f0-9]{64}")
_DIAGNOSTIC_SECRET = re.compile(
    r"(?i)(\b(?:password|passwd|token|secret|authorization|credential|api[-_]?key)\b\s*(?:=|:)\s*)(?:Bearer\s+)?(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)


class ImagePublicationError(RuntimeError):
    """A bounded, operator-actionable image publication failure."""


class ComposeRolloutError(ImagePublicationError):
    """A sealed Compose phase failed with redacted evidence for reconciliation."""

    def __init__(
        self,
        *,
        completed_phases: Sequence[Mapping[str, Any]],
        failed_services: Sequence[str],
        result: subprocess.CompletedProcess[str],
    ) -> None:
        super().__init__("sealed Compose rollout returned a non-zero exit status")
        self.evidence = {
            "completed_phases": [dict(phase) for phase in completed_phases],
            "failed_services": list(failed_services),
            "exit_code": int(result.returncode),
            "output_sha256": _output_fingerprint(result),
            "diagnostic": _build_failure_diagnostic(result),
        }


@dataclass(frozen=True)
class PublicationSpec:
    """One immutable-at-plan-time image publication declaration."""

    project: Path
    name: str
    image: str
    dockerfile: str
    context_paths: tuple[str, ...]
    source_root: str
    source_exclude_directories: tuple[str, ...]
    rollout_services: tuple[str, ...]
    migration_service: str | None
    workload_service: str
    workload_container: str
    health_url: str
    ready_url: str
    health_timeout_seconds: int
    compose_files: tuple[str, ...]
    compose_env_files: tuple[str, ...]
    compose_services: tuple[str, ...]
    compose_profiles: tuple[str, ...]
    compose_project_name: str

    def publication_document(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "image": self.image,
            "dockerfile": self.dockerfile,
            "context_paths": list(self.context_paths),
            "source_root": self.source_root,
            "source_exclude_directories": list(self.source_exclude_directories),
            "rollout_services": list(self.rollout_services),
            "migration_service": self.migration_service,
            "workload_service": self.workload_service,
            "workload_container": self.workload_container,
            "health_url": self.health_url,
            "ready_url": self.ready_url,
            "health_timeout_seconds": self.health_timeout_seconds,
            "compose_files": list(self.compose_files),
            "compose_env_files": list(self.compose_env_files),
            "compose_services": list(self.compose_services),
            "compose_profiles": list(self.compose_profiles),
            "compose_project_name": self.compose_project_name,
        }


@dataclass(frozen=True)
class ComposeMaterial:
    """One in-memory sealed Compose input capture and its secret-free evidence."""

    compose_payloads: tuple[bytes, ...]
    env_payloads: tuple[bytes, ...]
    evidence: dict[str, Any]


def normalize_publication_spec(
    *, project: str | Path, runtime_config: Mapping[str, Any], name: str
) -> PublicationSpec:
    """Read one narrow publication declaration from the project runtime file.

    The declaration gives the administrator enough context to approve a build,
    but is never sent across the broker socket.  Every accepted path is a
    lexical relative path beneath the real project directory.
    """

    root = _require_real_directory(Path(project), field="project")
    if _PUBLICATION_NAME.fullmatch(name) is None:
        raise ImagePublicationError("publication name is invalid")
    publications = runtime_config.get("image_publications")
    if not isinstance(publications, list):
        raise ImagePublicationError("runtime config has no image_publications list")
    selected = [item for item in publications if isinstance(item, Mapping) and item.get("name") == name]
    if len(selected) != 1:
        raise ImagePublicationError("publication name is absent or ambiguous")
    raw = selected[0]

    image = _require_image_reference(raw.get("image"), field="image")
    dockerfile = _require_relative_path(raw.get("dockerfile"), field="dockerfile")
    context_paths = _require_relative_path_list(
        raw.get("context_paths"), field="context_paths", minimum=1, maximum=MAX_CONTEXT_PATHS
    )
    if dockerfile not in context_paths:
        raise ImagePublicationError("dockerfile must be included in context_paths")
    _reject_overlapping_paths(context_paths)

    source = raw.get("source_fingerprint")
    if not isinstance(source, Mapping):
        raise ImagePublicationError("source_fingerprint must be an object")
    source_root = _require_relative_path(source.get("root"), field="source_fingerprint.root")
    if source_root not in context_paths:
        raise ImagePublicationError("source_fingerprint.root must be included in context_paths")
    source_excludes = _require_directory_name_list(
        source.get("exclude_directories"),
        field="source_fingerprint.exclude_directories",
        maximum=16,
    )

    docker = runtime_config.get("docker")
    if not isinstance(docker, Mapping):
        raise ImagePublicationError("image publication requires a declared docker object")
    compose_files = _require_relative_path_list(
        docker.get("compose_files") or docker.get("files"),
        field="docker.compose_files",
        minimum=1,
        maximum=16,
    )
    compose_env_files = _require_relative_path_list(
        docker.get("env_files") or docker.get("env_file") or [],
        field="docker.env_files",
        minimum=0,
        maximum=16,
    )
    compose_services = _require_service_list(
        docker.get("services"), field="docker.services", minimum=1, maximum=128
    )
    compose_profiles = _require_service_list(
        docker.get("profiles") or [], field="docker.profiles", minimum=0, maximum=64
    )
    project_name = str(docker.get("project_name") or root.name.lower())
    if _PROJECT_NAME.fullmatch(project_name) is None:
        raise ImagePublicationError("docker.project_name is invalid")

    rollout_services = _require_service_list(
        raw.get("rollout_services"), field="rollout_services", minimum=1, maximum=16
    )
    if not set(rollout_services).issubset(compose_services):
        raise ImagePublicationError("rollout_services must be declared docker services")
    workload_service = _require_service_name(raw.get("workload_service"), field="workload_service")
    if workload_service not in rollout_services:
        raise ImagePublicationError("workload_service must be included in rollout_services")
    migration_raw = raw.get("migration_service")
    migration_service = (
        _require_service_name(migration_raw, field="migration_service")
        if migration_raw is not None
        else None
    )
    if migration_service is not None and migration_service not in rollout_services:
        raise ImagePublicationError("migration_service must be included in rollout_services")
    container = raw.get("workload_container")
    if not isinstance(container, str) or _SERVICE_NAME.fullmatch(container) is None:
        raise ImagePublicationError("workload_container is invalid")

    health_url = _require_loopback_http_url(raw.get("health_url"), field="health_url")
    ready_url = _require_loopback_http_url(raw.get("ready_url"), field="ready_url")
    timeout = raw.get("health_timeout_seconds", 120)
    if type(timeout) is not int or not 10 <= timeout <= 600:
        raise ImagePublicationError("health_timeout_seconds must be from 10 through 600")

    _require_path_beneath(root, dockerfile, directory=False, field="dockerfile")
    _require_path_beneath(root, source_root, directory=True, field="source_fingerprint.root")
    for relative in context_paths:
        _require_path_beneath(root, relative, directory=None, field="context_paths")
    for relative in compose_files:
        _require_path_beneath(root, relative, directory=False, field="docker.compose_files")
    for relative in compose_env_files:
        _require_path_beneath(root, relative, directory=False, field="docker.env_files")

    return PublicationSpec(
        project=root,
        name=name,
        image=image,
        dockerfile=dockerfile,
        context_paths=context_paths,
        source_root=source_root,
        source_exclude_directories=source_excludes,
        rollout_services=rollout_services,
        migration_service=migration_service,
        workload_service=workload_service,
        workload_container=container,
        health_url=health_url,
        ready_url=ready_url,
        health_timeout_seconds=timeout,
        compose_files=compose_files,
        compose_env_files=compose_env_files,
        compose_services=compose_services,
        compose_profiles=compose_profiles,
        compose_project_name=project_name,
    )


def plan_publication(
    *,
    specification: PublicationSpec,
    artifact_root: Path,
    operation_id: str | None = None,
    service_uid: int = 0,
    broker_database_path: Path | None = None,
    compose_renderer: Callable[..., bytes] = render_compose_effective_model,
    compose_enrollment_verifier: Callable[[PublicationSpec, Mapping[str, Any], Any, Path], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Capture an immutable root-owned build snapshot without touching Docker."""

    normalized_operation_id = operation_id or str(uuid.uuid4())
    _require_canonical_operation_id(normalized_operation_id)
    root = _ensure_artifact_root(artifact_root, expected_uid=service_uid)
    operation_directory = root / normalized_operation_id
    if operation_directory.exists():
        raise ImagePublicationError("publication operation ID already exists")
    operation_directory.mkdir(mode=0o700)
    _require_private_directory(operation_directory, expected_uid=service_uid)

    try:
        snapshot_directory = operation_directory / "context"
        snapshot_directory.mkdir(mode=0o700)
        snapshot = _copy_context_snapshot(specification, snapshot_directory, expected_uid=service_uid)
        source_fingerprint = source_tree_fingerprint(
            snapshot_directory / specification.source_root,
            specification.source_exclude_directories,
        )
        compose = compose_evidence(
            specification,
            renderer=compose_renderer,
            broker_database_path=broker_database_path,
            enrollment_verifier=compose_enrollment_verifier,
        )
        previous_image_id = docker_image_id(specification.image, required=False)
        build_inputs = build_input_evidence(snapshot_directory, specification)
        manifest: dict[str, Any] = {
            "version": ARTIFACT_VERSION,
            "operation_id": normalized_operation_id,
            "status": "planned",
            "created_at": _utc_now(),
            "project": _project_identity(specification.project),
            "publication": specification.publication_document(),
            "snapshot": snapshot,
            "source": {"fingerprint": source_fingerprint},
            "compose": compose,
            "build_inputs": build_inputs,
            "previous_image_id": previous_image_id,
        }
        manifest["plan_fingerprint"] = _plan_fingerprint(manifest)
        write_manifest(operation_directory, manifest, expected_uid=service_uid)
        return publication_summary(manifest, artifact_directory=operation_directory)
    except BaseException:
        shutil.rmtree(operation_directory, ignore_errors=True)
        raise


def apply_publication(
    *,
    specification: PublicationSpec,
    artifact_root: Path,
    operation_id: str,
    confirmation_fingerprint: str,
    service_uid: int = 0,
    broker_database_path: Path | None = None,
    compose_renderer: Callable[..., bytes] = render_compose_effective_model,
    compose_enrollment_verifier: Callable[[PublicationSpec, Mapping[str, Any], Any, Path], dict[str, Any]] | None = None,
    docker_runner: Callable[[Sequence[str], float, Mapping[str, str]], subprocess.CompletedProcess[str]] | None = None,
    http_fetcher: Callable[[str, float], tuple[int, str]] | None = None,
    now: Callable[[], float] = time.time,
    rollout: bool = True,
) -> dict[str, Any]:
    """Build one planned snapshot and optionally recreate its declared workload."""

    directory, manifest = load_manifest(
        artifact_root=artifact_root,
        operation_id=operation_id,
        expected_uid=service_uid,
    )
    _require_plan_confirmation(manifest, confirmation_fingerprint)
    material = _require_plan_current(
        manifest,
        specification,
        broker_database_path=broker_database_path,
        compose_renderer=compose_renderer,
        compose_enrollment_verifier=compose_enrollment_verifier,
        now=now,
    )
    if manifest.get("status") not in {"planned", "build_failed", "build_outcome_uncertain"}:
        raise ImagePublicationError("publication is not in a buildable state")

    run_docker = docker_runner or _run_docker
    environment = _docker_environment()
    snapshot_directory = directory / "context"
    _require_private_directory(snapshot_directory, expected_uid=service_uid)
    _require_snapshot_integrity(manifest, snapshot_directory, specification)

    manifest["status"] = "building"
    manifest["build_started_at"] = _utc_now()
    write_manifest(directory, manifest, expected_uid=service_uid)
    build_command = build_command_for(manifest, snapshot_directory, specification)
    try:
        result = run_docker(build_command, BUILD_TIMEOUT_SECONDS, environment)
    except subprocess.TimeoutExpired as exc:
        manifest["status"] = "build_outcome_uncertain"
        manifest["build_error"] = "Docker build exceeded the bounded publication timeout."
        manifest["build_finished_at"] = _utc_now()
        write_manifest(directory, manifest, expected_uid=service_uid)
        raise ImagePublicationError("image build outcome is uncertain") from exc
    except OSError as exc:
        manifest["status"] = "build_failed"
        manifest["build_error"] = "Docker build could not be started."
        manifest["build_finished_at"] = _utc_now()
        write_manifest(directory, manifest, expected_uid=service_uid)
        raise ImagePublicationError("image build could not be started") from exc
    if not isinstance(result, subprocess.CompletedProcess):
        raise ImagePublicationError("Docker runner returned invalid build evidence")
    if result.returncode != 0:
        manifest["status"] = "build_failed"
        manifest["build_error"] = "Docker build returned a non-zero exit status."
        manifest["build_exit_code"] = result.returncode
        manifest["build_finished_at"] = _utc_now()
        manifest["build_output_sha256"] = _output_fingerprint(result)
        manifest["build_diagnostic"] = _build_failure_diagnostic(result)
        write_manifest(directory, manifest, expected_uid=service_uid)
        raise ImagePublicationError("image build failed")

    image = docker_image_evidence(specification.image, run_docker=run_docker, environment=environment)
    _require_image_labels(image, manifest)
    package_identity = installed_package_identity(
        specification.image, run_docker=run_docker, environment=environment
    )
    manifest["status"] = "built"
    manifest["build_finished_at"] = _utc_now()
    manifest["build_output_sha256"] = _output_fingerprint(result)
    manifest["image"] = image
    manifest["runtime_package"] = package_identity
    write_manifest(directory, manifest, expected_uid=service_uid)

    if not rollout:
        return publication_summary(manifest, artifact_directory=directory)

    manifest["status"] = "rolling_out"
    manifest["rollout_started_at"] = _utc_now()
    write_manifest(directory, manifest, expected_uid=service_uid)
    try:
        rollout = run_compose_rollout(
            specification,
            run_docker=run_docker,
            renderer=compose_renderer,
            material=material,
        )
    except BaseException as exc:
        manifest["status"] = "rollout_pending"
        manifest["rollout_error"] = "The sealed Compose rollout did not prove completion."
        if isinstance(exc, ComposeRolloutError):
            manifest["rollout_diagnostic"] = exc.evidence
        manifest["rollout_finished_at"] = _utc_now()
        write_manifest(directory, manifest, expected_uid=service_uid)
        raise ImagePublicationError("image rollout outcome is pending reconciliation") from exc
    manifest["rollout"] = rollout
    manifest["rollout_finished_at"] = _utc_now()
    write_manifest(directory, manifest, expected_uid=service_uid)

    verify = verify_published_runtime(
        specification,
        expected_image_id=str(image["image_id"]),
        expected_source_fingerprint=str(manifest["source"]["fingerprint"]),
        run_docker=run_docker,
        environment=environment,
        fetcher=http_fetcher or _fetch_http,
        now=now,
    )
    manifest["runtime_verification"] = verify
    live_source = source_tree_fingerprint(
        specification.project / specification.source_root,
        specification.source_exclude_directories,
    )
    manifest["current_source_fingerprint_after_rollout"] = live_source
    if live_source != manifest["source"]["fingerprint"]:
        manifest["status"] = "published_source_changed"
        write_manifest(directory, manifest, expected_uid=service_uid)
        raise ImagePublicationError(
            "source changed during publication; runtime matches the planned snapshot but is not source-current"
        )
    manifest["status"] = "published"
    manifest["published_at"] = _utc_now()
    write_manifest(directory, manifest, expected_uid=service_uid)
    return publication_summary(manifest, artifact_directory=directory)


def publication_status(
    *, artifact_root: Path, operation_id: str, service_uid: int = 0
) -> dict[str, Any]:
    directory, manifest = load_manifest(
        artifact_root=artifact_root,
        operation_id=operation_id,
        expected_uid=service_uid,
    )
    return publication_summary(manifest, artifact_directory=directory)


def rollback_publication(
    *,
    specification: PublicationSpec,
    artifact_root: Path,
    operation_id: str,
    previous_image_confirmation: str,
    service_uid: int = 0,
    broker_database_path: Path | None = None,
    compose_renderer: Callable[..., bytes] = render_compose_effective_model,
    compose_enrollment_verifier: Callable[[PublicationSpec, Mapping[str, Any], Any, Path], dict[str, Any]] | None = None,
    docker_runner: Callable[[Sequence[str], float, Mapping[str, str]], subprocess.CompletedProcess[str]] | None = None,
    http_fetcher: Callable[[str, float], tuple[int, str]] | None = None,
    now: Callable[[], float] = time.time,
) -> dict[str, Any]:
    """Restore the exact recorded prior image through the same sealed Compose path."""

    directory, manifest = load_manifest(
        artifact_root=artifact_root,
        operation_id=operation_id,
        expected_uid=service_uid,
    )
    if manifest.get("publication") != specification.publication_document():
        raise ImagePublicationError("current publication declaration differs from rollback plan")
    prior = manifest.get("previous_image_id")
    if not isinstance(prior, str) or _FINGERPRINT.fullmatch(prior.removeprefix("sha256:")) is None:
        raise ImagePublicationError("publication did not record a recoverable prior image ID")
    if previous_image_confirmation != prior:
        raise ImagePublicationError("rollback confirmation does not match the recorded prior image ID")
    material = _require_compose_matches_plan(
        manifest,
        specification,
        broker_database_path=broker_database_path,
        renderer=compose_renderer,
        compose_enrollment_verifier=compose_enrollment_verifier,
    )
    run_docker = docker_runner or _run_docker
    environment = _docker_environment()
    restore = run_docker(("docker", "tag", prior, specification.image), 60.0, environment)
    if not isinstance(restore, subprocess.CompletedProcess) or restore.returncode != 0:
        raise ImagePublicationError("prior image could not be retagged for rollback")
    manifest["rollback"] = {"status": "rolling_out", "image_id": prior, "started_at": _utc_now()}
    write_manifest(directory, manifest, expected_uid=service_uid)
    try:
        rollout = run_compose_rollout(
            specification,
            run_docker=run_docker,
            renderer=compose_renderer,
            material=material,
        )
        _wait_for_ready(specification.ready_url, specification.health_timeout_seconds, http_fetcher or _fetch_http, now)
        container_image = running_container_image_id(
            specification.workload_container, run_docker=run_docker, environment=environment
        )
        if container_image != prior:
            raise ImagePublicationError("rollback container did not use the recorded prior image")
    except BaseException as exc:
        manifest["rollback"] = {
            "status": "pending_reconciliation",
            "image_id": prior,
            "finished_at": _utc_now(),
        }
        write_manifest(directory, manifest, expected_uid=service_uid)
        raise ImagePublicationError("rollback outcome is pending reconciliation") from exc
    manifest["rollback"] = {
        "status": "completed",
        "image_id": prior,
        "rollout": rollout,
        "finished_at": _utc_now(),
    }
    write_manifest(directory, manifest, expected_uid=service_uid)
    return publication_summary(manifest, artifact_directory=directory)


def compose_evidence(
    specification: PublicationSpec,
    *,
    renderer: Callable[..., bytes] = render_compose_effective_model,
    broker_database_path: Path | None = None,
    enrollment_verifier: Callable[[PublicationSpec, Mapping[str, Any], Any, Path], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Render and validate the exact sealed Compose model without storing secrets."""

    return capture_compose_material(
        specification,
        renderer=renderer,
        broker_database_path=broker_database_path,
        enrollment_verifier=enrollment_verifier,
    ).evidence


def capture_compose_material(
    specification: PublicationSpec,
    *,
    renderer: Callable[..., bytes] = render_compose_effective_model,
    broker_database_path: Path | None = None,
    enrollment_verifier: Callable[[PublicationSpec, Mapping[str, Any], Any, Path], dict[str, Any]] | None = None,
) -> ComposeMaterial:
    """Capture one exact sealed Compose input set and its rendered-model evidence."""

    compose_payloads = tuple(
        _read_bounded_regular_file(specification.project / relative, 8 * 1024 * 1024)
        for relative in specification.compose_files
    )
    for payload in compose_payloads:
        require_sealable_compose_payload(payload)
    env_payloads = tuple(
        _read_private_environment_file(specification.project / relative)
        for relative in specification.compose_env_files
    )
    with _pinned_project_directory(specification.project) as pinned:
        rendered = renderer(
            compose_payloads=compose_payloads,
            env_payloads=env_payloads,
            profiles=specification.compose_profiles,
            declared_services=specification.compose_services,
            project_name=specification.compose_project_name,
            pinned_cwd=pinned,
        )
    # Rendering with approval permitted here only lets us classify the model.
    # The exact active broker enrollment is checked immediately below before
    # any result can be used for a build or Compose mutation.
    effective = require_effective_compose_model(
        rendered,
        declared_services=specification.compose_services,
        declared_profiles=specification.compose_profiles,
        project_name=specification.compose_project_name,
        host_access_approved=True,
    )
    try:
        model = json.loads(rendered)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ImagePublicationError("Compose renderer returned an invalid model") from exc
    services = model.get("services") if isinstance(model, Mapping) else None
    if not isinstance(services, Mapping):
        raise ImagePublicationError("Compose model has no services object")
    for service in specification.rollout_services:
        selected = services.get(service)
        if not isinstance(selected, Mapping):
            raise ImagePublicationError("publication rollout service is absent from rendered Compose")
        if "build" in selected:
            raise ImagePublicationError("sealed publication Compose model may not contain build")
    workload = services.get(specification.workload_service)
    if not isinstance(workload, Mapping) or workload.get("image") != specification.image:
        raise ImagePublicationError("workload service image does not match the publication image")
    evidence = {
        # Enrollment persists the canonical digest produced by the Compose
        # contract, not the renderer's incidental whitespace or key ordering.
        "model_sha256": effective.model_sha256,
        "compose_files": _file_hashes(specification.project, specification.compose_files),
        "env_files": _file_hashes(specification.project, specification.compose_env_files),
        "project_name": specification.compose_project_name,
    }
    verifier = enrollment_verifier or require_enrolled_compose_approval
    if broker_database_path is None:
        raise ImagePublicationError(
            "image publication requires an exact broker enrollment database"
        )
    enrollment = verifier(specification, evidence, effective, broker_database_path)
    if not isinstance(enrollment, dict):
        raise ImagePublicationError("broker enrollment verifier returned invalid evidence")
    evidence["enrollment"] = enrollment
    # Re-check the paths after payload capture. The actual rollout consumes the
    # captured bytes, while this check rejects a source/config swap during plan.
    if evidence["compose_files"] != _file_hashes(specification.project, specification.compose_files):
        raise ImagePublicationError("Compose files changed while publication evidence was captured")
    if evidence["env_files"] != _file_hashes(specification.project, specification.compose_env_files):
        raise ImagePublicationError("Compose environment files changed while publication evidence was captured")
    return ComposeMaterial(
        compose_payloads=compose_payloads,
        env_payloads=env_payloads,
        evidence=evidence,
    )


def require_enrolled_compose_approval(
    specification: PublicationSpec,
    evidence: Mapping[str, Any],
    effective: Any,
    database_path: Path,
) -> dict[str, Any]:
    """Bind publication to the live root-approved broker Compose enrollment.

    A runtime JSON file is user-writable, so a root publisher must not accept a
    host bind mount merely because that file labels it as intended. The service
    store is the durable administrator approval record. This read-only lookup
    also rejects a stale enrollment after any Compose or environment drift.
    """

    database = Path(database_path)
    _require_private_regular_file(database, expected_uid=0)
    try:
        connection = sqlite3.connect(
            f"file:{database}?mode=ro",
            uri=True,
            timeout=5.0,
        )
        connection.row_factory = sqlite3.Row
    except sqlite3.Error as exc:
        raise ImagePublicationError("broker enrollment database is unavailable") from exc
    try:
        rows = list(
            connection.execute(
                """
                SELECT d.compose_definition_id, d.definition_fingerprint,
                       d.project_name, d.cwd, d.enabled,
                       e.model_sha256, e.services_json, e.profiles_json,
                       e.host_access_risks_json, e.host_access_approved,
                       e.approved_by_uid, e.approved_at
                FROM broker_compose_definitions AS d
                JOIN repositories AS r ON r.repo_id = d.repo_id
                JOIN broker_compose_effective_model_evidence AS e
                  ON e.compose_definition_id = d.compose_definition_id
                 AND e.definition_fingerprint = d.definition_fingerprint
                WHERE r.canonical_root = ? AND d.cwd = ?
                  AND d.project_name = ? AND d.enabled = 1
                """,
                (
                    str(specification.project),
                    str(specification.project),
                    specification.compose_project_name,
                ),
            )
        )
    except sqlite3.Error as exc:
        raise ImagePublicationError("broker enrollment evidence could not be read") from exc
    finally:
        connection.close()
    if len(rows) != 1:
        raise ImagePublicationError("no single active broker Compose enrollment matches this publication")
    row = rows[0]
    expected_model = evidence.get("model_sha256")
    if (
        not isinstance(expected_model, str)
        or not expected_model.startswith("sha256:")
        or not _FINGERPRINT.fullmatch(expected_model.removeprefix("sha256:"))
    ):
        raise ImagePublicationError("publication Compose model digest is invalid")
    if row["model_sha256"] != expected_model:
        raise ImagePublicationError("broker-enrolled Compose model differs from the publication model")
    try:
        enrolled_services = json.loads(str(row["services_json"]))
        enrolled_profiles = json.loads(str(row["profiles_json"]))
        enrolled_risks = json.loads(str(row["host_access_risks_json"]))
    except json.JSONDecodeError as exc:
        raise ImagePublicationError("broker Compose enrollment evidence is malformed") from exc
    if enrolled_services != sorted(specification.compose_services):
        raise ImagePublicationError("broker-enrolled Compose services differ from publication services")
    if enrolled_profiles != sorted(specification.compose_profiles):
        raise ImagePublicationError("broker-enrolled Compose profiles differ from publication profiles")
    expected_risks = sorted(getattr(effective, "host_access_risks", ()))
    if enrolled_risks != expected_risks:
        raise ImagePublicationError("broker-enrolled host-access risks differ from the publication model")
    if expected_risks and int(row["host_access_approved"]) != 1:
        raise ImagePublicationError("effective Compose model requires an existing explicit host-access approval")
    file_rows = _enrollment_file_rows(database, str(row["compose_definition_id"]), environment=False)
    env_rows = _enrollment_file_rows(database, str(row["compose_definition_id"]), environment=True)
    expected_file_hashes = [str(item.get("sha256")) for item in evidence.get("compose_files") or ()]
    expected_env_hashes = [str(item.get("sha256")) for item in evidence.get("env_files") or ()]
    if file_rows != expected_file_hashes or env_rows != expected_env_hashes:
        raise ImagePublicationError("broker-enrolled Compose input hashes differ from publication inputs")
    definition_fingerprint = row["definition_fingerprint"]
    if not isinstance(definition_fingerprint, str) or not definition_fingerprint.startswith("sha256:"):
        raise ImagePublicationError("broker Compose enrollment has an invalid definition fingerprint")
    return {
        "compose_definition_id": str(row["compose_definition_id"]),
        "definition_fingerprint": definition_fingerprint,
        "model_sha256": str(row["model_sha256"]),
        "host_access_approved": bool(row["host_access_approved"]),
        "approved_by_uid": (
            int(row["approved_by_uid"])
            if row["approved_by_uid"] is not None
            else None
        ),
        "approved_at": str(row["approved_at"]) if row["approved_at"] is not None else None,
    }


def _enrollment_file_rows(
    database: Path, compose_definition_id: str, *, environment: bool
) -> list[str]:
    table = "broker_compose_env_file_evidence" if environment else "broker_compose_file_evidence"
    try:
        connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=5.0)
        connection.row_factory = sqlite3.Row
        rows = list(
            connection.execute(
                f"SELECT ordinal, content_sha256 FROM {table} WHERE compose_definition_id = ? ORDER BY ordinal",
                (compose_definition_id,),
            )
        )
    except sqlite3.Error as exc:
        raise ImagePublicationError("broker Compose file evidence could not be read") from exc
    finally:
        with suppress(UnboundLocalError):
            connection.close()
    return [str(row["content_sha256"]) for row in rows]


def build_input_evidence(snapshot_root: Path, specification: PublicationSpec) -> dict[str, Any]:
    """Return reproducibility evidence from the root-owned snapshot, not live files."""

    dockerfile = snapshot_root / specification.dockerfile
    payload = _read_bounded_regular_file(dockerfile, 8 * 1024 * 1024)
    lock_files: list[dict[str, str]] = []
    for path in sorted(snapshot_root.rglob("packages.lock.json")):
        if path.is_symlink() or not path.is_file():
            continue
        lock_files.append(
            {
                "path": path.relative_to(snapshot_root).as_posix(),
                "sha256": _sha256_file(path),
            }
        )
    base_images = _dockerfile_base_images(payload)
    if not base_images:
        raise ImagePublicationError("Dockerfile must declare digest-pinned base images")
    return {
        "dockerfile_sha256": hashlib.sha256(payload).hexdigest(),
        "lock_files": lock_files,
        "base_images": base_images,
    }


def source_tree_fingerprint(root: Path, excluded_directories: Sequence[str]) -> str:
    """Match the worker Dockerfile's sorted ``sha256sum`` tree algorithm."""

    root = _require_real_directory(root, field="source fingerprint root")
    excluded = frozenset(excluded_directories)
    records: list[tuple[bytes, bytes]] = []
    for current_name, directory_names, file_names in os.walk(root, topdown=True, followlinks=False):
        current = Path(current_name)
        kept_directories: list[str] = []
        for directory_name in sorted(directory_names):
            child = current / directory_name
            metadata = child.lstat()
            if current == root and directory_name in excluded:
                continue
            if stat.S_ISLNK(metadata.st_mode):
                continue
            if not stat.S_ISDIR(metadata.st_mode):
                raise ImagePublicationError("source fingerprint tree contains an invalid directory")
            kept_directories.append(directory_name)
        directory_names[:] = kept_directories
        for file_name in sorted(file_names):
            path = current / file_name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                continue
            relative = path.relative_to(root).as_posix()
            if "\\" in relative or "\n" in relative:
                raise ImagePublicationError("source fingerprint paths must be newline and backslash free")
            digest = _sha256_file(path)
            records.append((relative.encode("utf-8"), f"{digest}  ./{relative}\n".encode("utf-8")))
    combined = hashlib.sha256()
    for _relative, record in sorted(records, key=lambda item: item[0]):
        combined.update(record)
    return combined.hexdigest()


def build_command_for(
    manifest: Mapping[str, Any], snapshot_root: Path, specification: PublicationSpec
) -> tuple[str, ...]:
    """Return the only Docker build argv accepted by this publisher."""

    source = manifest.get("source")
    snapshot = manifest.get("snapshot")
    if not isinstance(source, Mapping) or not isinstance(snapshot, Mapping):
        raise ImagePublicationError("publication manifest is malformed")
    source_fingerprint = source.get("fingerprint")
    input_fingerprint = snapshot.get("input_manifest_sha256")
    if not isinstance(source_fingerprint, str) or _FINGERPRINT.fullmatch(source_fingerprint) is None:
        raise ImagePublicationError("publication source fingerprint is invalid")
    if not isinstance(input_fingerprint, str) or _FINGERPRINT.fullmatch(input_fingerprint) is None:
        raise ImagePublicationError("publication input fingerprint is invalid")
    dockerfile = snapshot_root / specification.dockerfile
    return (
        "docker",
        "build",
        "--pull=false",
        "--label",
        f"io.devcoordinator.publication={specification.name}",
        "--label",
        f"io.devcoordinator.source-fingerprint={source_fingerprint}",
        "--label",
        f"io.devcoordinator.input-fingerprint={input_fingerprint}",
        "--build-arg",
        f"DEVCOORDINATOR_SOURCE_FINGERPRINT={source_fingerprint}",
        "--file",
        str(dockerfile),
        "--tag",
        specification.image,
        str(snapshot_root),
    )


def publication_summary(manifest: Mapping[str, Any], *, artifact_directory: Path) -> dict[str, Any]:
    """Return useful evidence without exposing environment payloads or build logs."""

    return {
        "operation_id": manifest.get("operation_id"),
        "status": manifest.get("status"),
        "publication": (manifest.get("publication") or {}).get("name"),
        "plan_fingerprint": manifest.get("plan_fingerprint"),
        "source_fingerprint": (manifest.get("source") or {}).get("fingerprint"),
        "previous_image_id": manifest.get("previous_image_id"),
        "image_id": (manifest.get("image") or {}).get("image_id"),
        "artifact_directory": str(artifact_directory),
        "runtime_verification": manifest.get("runtime_verification"),
        "rollback": manifest.get("rollback"),
    }


def load_manifest(
    *, artifact_root: Path, operation_id: str, expected_uid: int
) -> tuple[Path, dict[str, Any]]:
    _require_canonical_operation_id(operation_id)
    root = _ensure_artifact_root(artifact_root, expected_uid=expected_uid)
    directory = root / operation_id
    _require_private_directory(directory, expected_uid=expected_uid)
    path = directory / "manifest.json"
    metadata = _require_private_regular_file(path, expected_uid=expected_uid)
    if metadata.st_size > 1024 * 1024:
        raise ImagePublicationError("publication manifest exceeds its bounded size")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ImagePublicationError("publication manifest is unreadable") from exc
    if not isinstance(document, dict) or document.get("version") != ARTIFACT_VERSION:
        raise ImagePublicationError("publication manifest is invalid")
    if document.get("operation_id") != operation_id:
        raise ImagePublicationError("publication manifest operation ID does not match its directory")
    plan = document.get("plan_fingerprint")
    if not isinstance(plan, str) or _FINGERPRINT.fullmatch(plan) is None:
        raise ImagePublicationError("publication manifest has no valid plan fingerprint")
    return directory, document


def write_manifest(directory: Path, manifest: Mapping[str, Any], *, expected_uid: int) -> None:
    _require_private_directory(directory, expected_uid=expected_uid)
    payload = _canonical_json(manifest).encode("utf-8") + b"\n"
    if len(payload) > 1024 * 1024:
        raise ImagePublicationError("publication manifest exceeds its bounded size")
    temporary = directory / ".manifest.tmp"
    descriptor = -1
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("manifest write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    except OSError as exc:
        raise ImagePublicationError("publication manifest could not be written") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        os.replace(temporary, directory / "manifest.json")
        os.chmod(directory / "manifest.json", 0o600)
        directory_descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as exc:
        raise ImagePublicationError("publication manifest could not be committed") from exc


def docker_image_id(image: str, *, required: bool) -> str | None:
    result = _run_docker(("docker", "image", "inspect", "--format", "{{.Id}}", image), 30.0, _docker_environment())
    if result.returncode != 0:
        if required:
            raise ImagePublicationError("published image cannot be inspected")
        return None
    value = str(result.stdout or "").strip()
    if not value.startswith("sha256:") or _FINGERPRINT.fullmatch(value.removeprefix("sha256:")) is None:
        raise ImagePublicationError("Docker returned an invalid image ID")
    return value


def docker_image_evidence(
    image: str,
    *,
    run_docker: Callable[[Sequence[str], float, Mapping[str, str]], subprocess.CompletedProcess[str]],
    environment: Mapping[str, str],
) -> dict[str, Any]:
    result = run_docker(("docker", "image", "inspect", image), 30.0, environment)
    if not isinstance(result, subprocess.CompletedProcess) or result.returncode != 0:
        raise ImagePublicationError("published image cannot be inspected")
    try:
        document = json.loads(str(result.stdout or ""))
    except json.JSONDecodeError as exc:
        raise ImagePublicationError("Docker returned invalid image inspection JSON") from exc
    if not isinstance(document, list) or len(document) != 1 or not isinstance(document[0], Mapping):
        raise ImagePublicationError("Docker returned ambiguous image inspection evidence")
    value = document[0]
    image_id = value.get("Id")
    if not isinstance(image_id, str) or not image_id.startswith("sha256:") or _FINGERPRINT.fullmatch(image_id.removeprefix("sha256:")) is None:
        raise ImagePublicationError("Docker image evidence has an invalid image ID")
    labels = ((value.get("Config") or {}).get("Labels") if isinstance(value.get("Config"), Mapping) else None) or {}
    if not isinstance(labels, Mapping):
        raise ImagePublicationError("Docker image evidence has invalid labels")
    repo_digests = value.get("RepoDigests")
    if repo_digests is None:
        repo_digests = []
    if not isinstance(repo_digests, list) or not all(isinstance(item, str) for item in repo_digests):
        raise ImagePublicationError("Docker image evidence has invalid repository digests")
    return {
        "image_id": image_id,
        "repo_digests": sorted(repo_digests),
        "labels": {
            key: str(labels[key])
            for key in (
                "io.devcoordinator.publication",
                "io.devcoordinator.source-fingerprint",
                "io.devcoordinator.input-fingerprint",
            )
            if key in labels
        },
    }


def installed_package_identity(
    image: str,
    *,
    run_docker: Callable[[Sequence[str], float, Mapping[str, str]], subprocess.CompletedProcess[str]],
    environment: Mapping[str, str],
) -> str:
    command = (
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--user",
        "1654:1654",
        "--entrypoint",
        "/bin/sh",
        image,
        "-ec",
        "dpkg-query -W -f='${Package}=${Version}:${Architecture}\\n' libgssapi-krb5-2",
    )
    result = run_docker(command, 60.0, environment)
    if not isinstance(result, subprocess.CompletedProcess) or result.returncode != 0:
        raise ImagePublicationError("published image does not prove its libgssapi package identity")
    value = str(result.stdout or "").strip()
    if not value.startswith("libgssapi-krb5-2=") or len(value) > 512 or "\n" in value:
        raise ImagePublicationError("published image returned an invalid libgssapi package identity")
    return value


def run_compose_rollout(
    specification: PublicationSpec,
    *,
    run_docker: Callable[[Sequence[str], float, Mapping[str, str]], subprocess.CompletedProcess[str]],
    renderer: Callable[..., bytes] = render_compose_effective_model,
    material: ComposeMaterial | None = None,
) -> dict[str, Any]:
    """Use sealed current Compose bytes to recreate the declared migration/workload chain."""

    captured = material or capture_compose_material(specification, renderer=renderer)
    docker = _resolve_docker_executable()
    environment = _docker_environment(docker)
    phases: list[dict[str, Any]] = []
    phase_services: list[tuple[str, ...]] = []
    if specification.migration_service is not None:
        phase_services.append((specification.migration_service,))
    rollout_services = tuple(
        service
        for service in specification.rollout_services
        if service != specification.migration_service
    )
    if rollout_services:
        phase_services.append(rollout_services)
    with _pinned_project_directory(specification.project) as pinned:
        with _sealed_compose_input_snapshots(
            compose_payloads=captured.compose_payloads,
            env_payloads=captured.env_payloads,
            action="up",
        ) as (sealed_files, sealed_env_files):
            cleanup_command: list[str] = [
                docker,
                "compose",
                "--project-directory",
                ".",
                "--project-name",
                specification.compose_project_name,
            ]
            for env_file in sealed_env_files:
                cleanup_command.extend(("--env-file", env_file))
            for compose_file in sealed_files:
                cleanup_command.extend(("--file", compose_file))
            cleanup_command.extend(("rm", "--force", "--stop"))
            cleanup_command.extend(specification.rollout_services)
            cleanup_result = _run_compose_command(
                tuple(cleanup_command),
                pinned,
                COMPOSE_TIMEOUT_SECONDS,
                environment,
            )
            if cleanup_result.returncode != 0:
                raise ComposeRolloutError(
                    completed_phases=phases,
                    failed_services=specification.rollout_services,
                    result=cleanup_result,
                )
            phases.append(
                {
                    "action": "clean-cutover",
                    "services": list(specification.rollout_services),
                    "output_sha256": _output_fingerprint(cleanup_result),
                }
            )
            for services in phase_services:
                command: list[str] = [
                    docker,
                    "compose",
                    "--project-directory",
                    ".",
                    "--project-name",
                    specification.compose_project_name,
                ]
                for env_file in sealed_env_files:
                    command.extend(("--env-file", env_file))
                for compose_file in sealed_files:
                    command.extend(("--file", compose_file))
                command.extend(
                    (
                        "up",
                        "--detach",
                        "--no-build",
                        "--force-recreate",
                        "--wait",
                        "--wait-timeout",
                        str(specification.health_timeout_seconds),
                    )
                )
                command.extend(services)
                result = _run_compose_command(tuple(command), pinned, COMPOSE_TIMEOUT_SECONDS, environment)
                if result.returncode != 0:
                    raise ComposeRolloutError(
                        completed_phases=phases,
                        failed_services=services,
                        result=result,
                    )
                phases.append(
                    {
                        "action": "up",
                        "services": list(services),
                        "output_sha256": _output_fingerprint(result),
                    }
                )
    return {"phases": phases, "no_build": True, "force_recreate": True}


def verify_published_runtime(
    specification: PublicationSpec,
    *,
    expected_image_id: str,
    expected_source_fingerprint: str,
    run_docker: Callable[[Sequence[str], float, Mapping[str, str]], subprocess.CompletedProcess[str]],
    environment: Mapping[str, str],
    fetcher: Callable[[str, float], tuple[int, str]],
    now: Callable[[], float],
) -> dict[str, Any]:
    _wait_for_ready(specification.ready_url, specification.health_timeout_seconds, fetcher, now)
    health_status, health_body = _wait_for_http(
        specification.health_url,
        specification.health_timeout_seconds,
        fetcher,
        now,
        require_body=True,
    )
    if health_status != 200:
        raise ImagePublicationError("published worker health endpoint did not return HTTP 200")
    try:
        health = json.loads(health_body)
    except json.JSONDecodeError as exc:
        raise ImagePublicationError("published worker health response is not JSON") from exc
    actual = _nested_value(health, ("build", "sourceFingerprint"))
    if actual != expected_source_fingerprint:
        raise ImagePublicationError("published worker source fingerprint does not match the planned snapshot")
    running_image = running_container_image_id(
        specification.workload_container,
        run_docker=run_docker,
        environment=environment,
    )
    if running_image != expected_image_id:
        raise ImagePublicationError("published workload container does not use the built image ID")
    return {
        "ready_url": specification.ready_url,
        "health_url": specification.health_url,
        "source_fingerprint": actual,
        "image_id": running_image,
    }


def running_container_image_id(
    container: str,
    *,
    run_docker: Callable[[Sequence[str], float, Mapping[str, str]], subprocess.CompletedProcess[str]],
    environment: Mapping[str, str],
) -> str:
    result = run_docker(("docker", "inspect", "--format", "{{.Image}}", container), 30.0, environment)
    if not isinstance(result, subprocess.CompletedProcess) or result.returncode != 0:
        raise ImagePublicationError("workload container cannot be inspected")
    value = str(result.stdout or "").strip()
    if not value.startswith("sha256:") or _FINGERPRINT.fullmatch(value.removeprefix("sha256:")) is None:
        raise ImagePublicationError("workload container returned an invalid image ID")
    return value


def _copy_context_snapshot(
    specification: PublicationSpec, snapshot_root: Path, *, expected_uid: int
) -> dict[str, Any]:
    _require_private_directory(snapshot_root, expected_uid=expected_uid)
    total_bytes = 0
    total_files = 0
    root_fd = _open_directory_no_follow(specification.project)
    try:
        for relative in specification.context_paths:
            source_parts = tuple(Path(relative).parts)
            destination = snapshot_root.joinpath(*source_parts)
            if destination.exists():
                raise ImagePublicationError("publication context paths overlap")
            _copy_path_from_directory(
                root_fd,
                source_parts,
                destination,
                source_root_parts=tuple(Path(specification.source_root).parts),
                source_excludes=frozenset(specification.source_exclude_directories),
                state={"bytes": total_bytes, "files": total_files},
            )
            # The state is returned by the mutable holder set by the copy routine.
            copied_state = _copy_state(destination)
            total_bytes += copied_state["bytes"]
            total_files += copied_state["files"]
    finally:
        os.close(root_fd)
    manifest = _snapshot_manifest(snapshot_root)
    return {
        "context_directory": "context",
        "file_count": manifest["file_count"],
        "byte_count": manifest["byte_count"],
        "input_manifest_sha256": manifest["sha256"],
    }


def _copy_state(destination: Path) -> dict[str, int]:
    """Count the copied immutable destination once without trusting source metadata."""

    files = 0
    total = 0
    if destination.is_file():
        return {"files": 1, "bytes": destination.stat().st_size}
    for current, _directories, names in os.walk(destination, followlinks=False):
        for name in names:
            path = Path(current) / name
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise ImagePublicationError("snapshot contains an invalid file type")
            files += 1
            total += metadata.st_size
    return {"files": files, "bytes": total}


def _copy_path_from_directory(
    directory_fd: int,
    parts: tuple[str, ...],
    destination: Path,
    *,
    source_root_parts: tuple[str, ...],
    source_excludes: frozenset[str],
    state: dict[str, int],
) -> None:
    if not parts:
        raise ImagePublicationError("publication context path is empty")
    try:
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        raise ImagePublicationError("publication snapshot parent could not be created") from exc
    parent_metadata = destination.parent.lstat()
    if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(parent_metadata.st_mode):
        raise ImagePublicationError("publication snapshot parent is invalid")
    current_fd = os.dup(directory_fd)
    try:
        for part in parts[:-1]:
            next_fd = _open_child_directory(current_fd, part)
            os.close(current_fd)
            current_fd = next_fd
        _copy_entry(
            current_fd,
            parts[-1],
            destination,
            relative_parts=parts,
            source_root_parts=source_root_parts,
            source_excludes=source_excludes,
            state=state,
        )
    finally:
        os.close(current_fd)


def _copy_entry(
    parent_fd: int,
    name: str,
    destination: Path,
    *,
    relative_parts: tuple[str, ...],
    source_root_parts: tuple[str, ...],
    source_excludes: frozenset[str],
    state: dict[str, int],
) -> None:
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise ImagePublicationError("publication context input is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise ImagePublicationError("publication context may not contain symbolic links")
    if stat.S_ISREG(metadata.st_mode):
        _copy_regular_file(parent_fd, name, destination, metadata, state)
        return
    if not stat.S_ISDIR(metadata.st_mode):
        raise ImagePublicationError("publication context contains an unsupported file type")
    destination.mkdir(mode=0o700)
    source_fd = _open_child_directory(parent_fd, name)
    try:
        for child in sorted(os.listdir(source_fd)):
            child_relative = (*relative_parts, child)
            if (
                len(child_relative) == len(source_root_parts) + 1
                and child_relative[: len(source_root_parts)] == source_root_parts
                and child in source_excludes
            ):
                continue
            _copy_entry(
                source_fd,
                child,
                destination / child,
                relative_parts=child_relative,
                source_root_parts=source_root_parts,
                source_excludes=source_excludes,
                state=state,
            )
    finally:
        os.close(source_fd)


def _copy_regular_file(
    parent_fd: int,
    name: str,
    destination: Path,
    metadata: os.stat_result,
    state: dict[str, int],
) -> None:
    if metadata.st_size < 0 or metadata.st_size > MAX_CONTEXT_FILE_BYTES:
        raise ImagePublicationError("publication context file exceeds its bounded size")
    next_files = state["files"] + 1
    next_bytes = state["bytes"] + int(metadata.st_size)
    if next_files > MAX_CONTEXT_FILES or next_bytes > MAX_CONTEXT_TOTAL_BYTES:
        raise ImagePublicationError("publication context exceeds its bounded size")
    read_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        read_flags |= os.O_NOFOLLOW
    source_fd = -1
    destination_fd = -1
    try:
        source_fd = os.open(name, read_flags, dir_fd=parent_fd)
        opened = os.fstat(source_fd)
        if not stat.S_ISREG(opened.st_mode) or stat.S_ISLNK(opened.st_mode):
            raise ImagePublicationError("publication context file changed type while copying")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        mode = 0o600 | (stat.S_IMODE(opened.st_mode) & 0o111)
        destination_fd = os.open(destination, flags, mode)
        copied = 0
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            copied += len(chunk)
            if copied > MAX_CONTEXT_FILE_BYTES:
                raise ImagePublicationError("publication context file exceeded its bounded size while copying")
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise OSError("publication context write made no progress")
                view = view[written:]
        os.fsync(destination_fd)
        state["files"] = next_files
        state["bytes"] = state["bytes"] - int(metadata.st_size) + copied
        if state["bytes"] > MAX_CONTEXT_TOTAL_BYTES:
            raise ImagePublicationError("publication context exceeded its bounded size while copying")
    except OSError as exc:
        raise ImagePublicationError("publication context file could not be copied") from exc
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
        if source_fd >= 0:
            os.close(source_fd)


def _snapshot_manifest(snapshot_root: Path) -> dict[str, Any]:
    records: list[tuple[str, str, int]] = []
    total_bytes = 0
    for current, directories, names in os.walk(snapshot_root, topdown=True, followlinks=False):
        current_path = Path(current)
        directories[:] = sorted(directories)
        for name in sorted(names):
            path = current_path / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise ImagePublicationError("snapshot contains an unsupported file type")
            relative = path.relative_to(snapshot_root).as_posix()
            if "\n" in relative or "\\" in relative:
                raise ImagePublicationError("snapshot paths must be newline and backslash free")
            total_bytes += metadata.st_size
            records.append((relative, _sha256_file(path), stat.S_IMODE(metadata.st_mode)))
    if len(records) > MAX_CONTEXT_FILES or total_bytes > MAX_CONTEXT_TOTAL_BYTES:
        raise ImagePublicationError("snapshot exceeds its bounded size")
    digest = hashlib.sha256()
    for relative, file_digest, mode in records:
        digest.update(f"{file_digest} {mode:04o} {relative}\n".encode("utf-8"))
    return {"file_count": len(records), "byte_count": total_bytes, "sha256": digest.hexdigest()}


def _require_plan_confirmation(manifest: Mapping[str, Any], confirmation: str) -> None:
    expected = manifest.get("plan_fingerprint")
    if not isinstance(expected, str) or _FINGERPRINT.fullmatch(expected) is None:
        raise ImagePublicationError("publication manifest has no valid plan fingerprint")
    if confirmation != expected:
        raise ImagePublicationError("publication confirmation does not match the exact planned snapshot")


def _require_plan_current(
    manifest: Mapping[str, Any],
    specification: PublicationSpec,
    *,
    broker_database_path: Path | None,
    compose_renderer: Callable[..., bytes],
    compose_enrollment_verifier: Callable[[PublicationSpec, Mapping[str, Any], Any, Path], dict[str, Any]] | None,
    now: Callable[[], float],
) -> ComposeMaterial:
    publication = manifest.get("publication")
    if publication != specification.publication_document():
        raise ImagePublicationError("current publication declaration differs from the planned declaration")
    created_at = manifest.get("created_at")
    try:
        created = datetime.fromisoformat(str(created_at).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError, OverflowError) as exc:
        raise ImagePublicationError("publication plan has an invalid creation timestamp") from exc
    if now() - created > MAX_PLAN_AGE_SECONDS:
        raise ImagePublicationError("publication plan expired; create a fresh source snapshot")
    expected_project = manifest.get("project")
    if expected_project != _project_identity(specification.project):
        raise ImagePublicationError("project identity changed since image publication was planned")
    expected_source = ((manifest.get("source") or {}).get("fingerprint"))
    actual_source = source_tree_fingerprint(
        specification.project / specification.source_root,
        specification.source_exclude_directories,
    )
    if expected_source != actual_source:
        raise ImagePublicationError("source changed since image publication was planned")
    material = _require_compose_matches_plan(
        manifest,
        specification,
        broker_database_path=broker_database_path,
        renderer=compose_renderer,
        compose_enrollment_verifier=compose_enrollment_verifier,
    )
    planned_previous = manifest.get("previous_image_id")
    current_previous = docker_image_id(specification.image, required=False)
    if planned_previous != current_previous:
        raise ImagePublicationError("publication image tag changed since the plan was created")
    return material


def _require_compose_matches_plan(
    manifest: Mapping[str, Any],
    specification: PublicationSpec,
    *,
    broker_database_path: Path | None,
    renderer: Callable[..., bytes],
    compose_enrollment_verifier: Callable[[PublicationSpec, Mapping[str, Any], Any, Path], dict[str, Any]] | None,
) -> ComposeMaterial:
    expected = manifest.get("compose")
    if not isinstance(expected, Mapping):
        raise ImagePublicationError("publication manifest has no Compose evidence")
    material = capture_compose_material(
        specification,
        renderer=renderer,
        broker_database_path=broker_database_path,
        enrollment_verifier=compose_enrollment_verifier,
    )
    if material.evidence != dict(expected):
        raise ImagePublicationError("sealed Compose model or inputs changed since image publication was planned")
    return material


def _require_snapshot_integrity(
    manifest: Mapping[str, Any], snapshot_root: Path, specification: PublicationSpec
) -> None:
    snapshot = manifest.get("snapshot")
    source = manifest.get("source")
    if not isinstance(snapshot, Mapping) or not isinstance(source, Mapping):
        raise ImagePublicationError("publication manifest has invalid snapshot evidence")
    if snapshot.get("context_directory") != "context":
        raise ImagePublicationError("publication manifest has an invalid snapshot directory")
    expected_snapshot = {
        "file_count": snapshot.get("file_count"),
        "byte_count": snapshot.get("byte_count"),
        "sha256": snapshot.get("input_manifest_sha256"),
    }
    actual_snapshot = _snapshot_manifest(snapshot_root)
    if actual_snapshot != expected_snapshot:
        raise ImagePublicationError("root-owned publication snapshot no longer matches its manifest")
    actual_source = source_tree_fingerprint(
        snapshot_root / specification.source_root,
        specification.source_exclude_directories,
    )
    if actual_source != source.get("fingerprint"):
        raise ImagePublicationError("publication snapshot source fingerprint changed")
    actual_inputs = build_input_evidence(snapshot_root, specification)
    if actual_inputs != manifest.get("build_inputs"):
        raise ImagePublicationError("publication snapshot build inputs changed")


def _require_image_labels(image: Mapping[str, Any], manifest: Mapping[str, Any]) -> None:
    labels = image.get("labels")
    source = (manifest.get("source") or {}).get("fingerprint")
    input_fingerprint = (manifest.get("snapshot") or {}).get("input_manifest_sha256")
    publication = (manifest.get("publication") or {}).get("name")
    if not isinstance(labels, Mapping) or labels != {
        "io.devcoordinator.publication": publication,
        "io.devcoordinator.source-fingerprint": source,
        "io.devcoordinator.input-fingerprint": input_fingerprint,
    }:
        raise ImagePublicationError("built image labels do not prove the planned snapshot")


def _plan_fingerprint(manifest: Mapping[str, Any]) -> str:
    binding = {
        key: manifest[key]
        for key in (
            "version",
            "operation_id",
            "project",
            "publication",
            "snapshot",
            "source",
            "compose",
            "build_inputs",
            "previous_image_id",
        )
    }
    return hashlib.sha256(_canonical_json(binding).encode("utf-8")).hexdigest()


def _project_identity(root: Path) -> dict[str, Any]:
    metadata = _require_real_directory(root, field="project")
    return {"path": str(root), "device": metadata.stat().st_dev, "inode": metadata.stat().st_ino}


def _output_fingerprint(result: subprocess.CompletedProcess[str]) -> str:
    stdout = str(result.stdout or "").encode("utf-8", errors="replace")
    stderr = str(result.stderr or "").encode("utf-8", errors="replace")
    return hashlib.sha256(stdout + b"\0" + stderr).hexdigest()


def _build_failure_diagnostic(result: subprocess.CompletedProcess[str]) -> dict[str, str]:
    """Retain bounded, redacted Docker failure evidence in the private artifact."""

    return {
        "stdout_tail": _redacted_diagnostic_tail(result.stdout),
        "stderr_tail": _redacted_diagnostic_tail(result.stderr),
    }


def _redacted_diagnostic_tail(value: Any) -> str:
    text = str(value or "").replace("\x00", "")
    redacted = _DIAGNOSTIC_SECRET.sub(r"\1<redacted>", text)
    if len(redacted) <= BUILD_DIAGNOSTIC_LIMIT:
        return redacted
    return "..." + redacted[-BUILD_DIAGNOSTIC_LIMIT:]


def _dockerfile_base_images(payload: bytes) -> list[str]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ImagePublicationError("Dockerfile must be UTF-8 text") from exc
    values: list[str] = []
    for line in text.splitlines():
        match = re.fullmatch(r"\s*ARG\s+[A-Za-z_][A-Za-z0-9_]*_IMAGE=([^\s]+)\s*", line)
        if match is None:
            continue
        image = match.group(1)
        if "@sha256:" not in image:
            raise ImagePublicationError("Dockerfile base image ARG is not digest-pinned")
        digest = image.rsplit("@sha256:", 1)[1]
        if _FINGERPRINT.fullmatch(digest) is None:
            raise ImagePublicationError("Dockerfile base image digest is invalid")
        values.append(image)
    return values


def _require_relative_path(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ImagePublicationError(f"{field} must be a non-empty relative path")
    candidate = Path(value)
    if candidate.is_absolute() or value != candidate.as_posix() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise ImagePublicationError(f"{field} must be a normalized relative path")
    return value


def _require_relative_path_list(
    value: Any, *, field: str, minimum: int, maximum: int
) -> tuple[str, ...]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise ImagePublicationError(f"{field} must contain from {minimum} through {maximum} paths")
    normalized = tuple(_require_relative_path(item, field=field) for item in value)
    if len(set(normalized)) != len(normalized):
        raise ImagePublicationError(f"{field} paths must be unique")
    return normalized


def _require_directory_name_list(value: Any, *, field: str, maximum: int) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or len(value) > maximum:
        raise ImagePublicationError(f"{field} must contain at most {maximum} directory names")
    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item or Path(item).name != item or item in {".", ".."}:
            raise ImagePublicationError(f"{field} entries must be directory names")
        normalized.append(item)
    if len(set(normalized)) != len(normalized):
        raise ImagePublicationError(f"{field} directory names must be unique")
    return tuple(normalized)


def _require_service_name(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or _SERVICE_NAME.fullmatch(value) is None:
        raise ImagePublicationError(f"{field} is invalid")
    return value


def _require_service_list(value: Any, *, field: str, minimum: int, maximum: int) -> tuple[str, ...]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise ImagePublicationError(f"{field} must contain from {minimum} through {maximum} names")
    normalized = tuple(_require_service_name(item, field=field) for item in value)
    if len(set(normalized)) != len(normalized):
        raise ImagePublicationError(f"{field} names must be unique")
    return normalized


def _require_image_reference(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or _IMAGE_REFERENCE.fullmatch(value) is None or "@" in value:
        raise ImagePublicationError(f"{field} must be one bounded tagged image reference")
    return value


def _require_loopback_http_url(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or len(value) > 512 or "\x00" in value:
        raise ImagePublicationError(f"{field} is invalid")
    match = re.fullmatch(r"http://(127\.0\.0\.1|localhost):([1-9][0-9]{0,4})(/[^\s#]*)?", value)
    if match is None:
        raise ImagePublicationError(f"{field} must be an HTTP loopback URL")
    port = int(match.group(2))
    if not 1 <= port <= 65535:
        raise ImagePublicationError(f"{field} has an invalid port")
    return value


def _reject_overlapping_paths(paths: Sequence[str]) -> None:
    all_paths = [Path(item).parts for item in paths]
    for index, left in enumerate(all_paths):
        for right in all_paths[index + 1 :]:
            if left == right or left == right[: len(left)] or right == left[: len(right)]:
                raise ImagePublicationError("context_paths may not overlap")


def _require_path_beneath(root: Path, relative: str, *, directory: bool | None, field: str) -> Path:
    candidate = root / relative
    absolute = Path(os.path.abspath(candidate))
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ImagePublicationError(f"{field} is unavailable") from exc
    if absolute != resolved or root not in (resolved, *resolved.parents):
        raise ImagePublicationError(f"{field} contains a symbolic link or escapes the project")
    metadata = resolved.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        raise ImagePublicationError(f"{field} may not be a symbolic link")
    if directory is True and not stat.S_ISDIR(metadata.st_mode):
        raise ImagePublicationError(f"{field} must be a directory")
    if directory is False and not stat.S_ISREG(metadata.st_mode):
        raise ImagePublicationError(f"{field} must be a regular file")
    if directory is None and not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
        raise ImagePublicationError(f"{field} must be a regular file or directory")
    return resolved


def _require_real_directory(path: Path, *, field: str) -> Path:
    absolute = Path(os.path.abspath(path))
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ImagePublicationError(f"{field} is unavailable") from exc
    if absolute != resolved:
        raise ImagePublicationError(f"{field} contains a symbolic link")
    metadata = resolved.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ImagePublicationError(f"{field} must be a real directory")
    return resolved


def _ensure_artifact_root(path: Path, *, expected_uid: int) -> Path:
    root = Path(path)
    if not root.is_absolute():
        raise ImagePublicationError("publication artifact root must be absolute")
    if root.exists():
        _require_private_directory(root, expected_uid=expected_uid)
        return root
    parent = root.parent
    _require_private_directory(parent, expected_uid=expected_uid)
    try:
        root.mkdir(mode=0o700)
    except OSError as exc:
        raise ImagePublicationError("publication artifact root could not be created") from exc
    _require_private_directory(root, expected_uid=expected_uid)
    return root


def _require_private_directory(path: Path, *, expected_uid: int) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ImagePublicationError("publication artifact directory is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ImagePublicationError("publication artifact directory is not private and service-owned")


def _require_private_regular_file(path: Path, *, expected_uid: int) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ImagePublicationError("publication artifact file is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ImagePublicationError("publication artifact file is not private and service-owned")
    return metadata


def _open_directory_no_follow(path: Path) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ImagePublicationError("publication directory could not be opened without following links") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ImagePublicationError("publication path is not a directory")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _open_child_directory(parent_fd: int, name: str) -> int:
    if not name or name in {".", ".."} or "/" in name:
        raise ImagePublicationError("publication path component is invalid")
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise ImagePublicationError("publication directory input is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ImagePublicationError("publication directory input changed type")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


@contextmanager
def _pinned_project_directory(project: Path) -> Iterator[str]:
    descriptor = _open_directory_no_follow(project)
    try:
        yield f"/proc/{os.getpid()}/fd/{descriptor}"
    finally:
        os.close(descriptor)


def _read_bounded_regular_file(path: Path, maximum: int) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ImagePublicationError("publication input file is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ImagePublicationError("publication input must be a real regular file")
    if metadata.st_size < 0 or metadata.st_size > maximum:
        raise ImagePublicationError("publication input file exceeds its bounded size")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or stat.S_ISLNK(opened.st_mode):
            raise ImagePublicationError("publication input file changed type while reading")
        chunks: list[bytes] = []
        copied = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            copied += len(chunk)
            if copied > maximum:
                raise ImagePublicationError("publication input file exceeded its bounded size while reading")
            chunks.append(chunk)
        return b"".join(chunks)
    except OSError as exc:
        raise ImagePublicationError("publication input file could not be read") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_private_environment_file(path: Path) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ImagePublicationError("Compose environment file is unavailable") from exc
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ImagePublicationError("Compose environment file grants group or other access")
    return _read_bounded_regular_file(path, 1024 * 1024)


def _file_hashes(root: Path, paths: Sequence[str]) -> list[dict[str, str]]:
    return [
        {"path": relative, "sha256": _sha256_file(root / relative)}
        for relative in paths
    ]


def _sha256_file(path: Path) -> str:
    payload = _read_bounded_regular_file(path, MAX_CONTEXT_FILE_BYTES)
    return hashlib.sha256(payload).hexdigest()


def _docker_environment(docker_executable: str | None = None) -> dict[str, str]:
    executable = docker_executable or _resolve_docker_executable()
    environment = bounded_compose_environment(executable)
    # Keep image builds and Compose rollouts on the same deliberately service-owned
    # Docker credential/configuration surface as the broker unit.
    environment["DOCKER_CONFIG"] = "/var/lib/devcoordinator/docker"
    return environment


def _run_docker(
    command: Sequence[str], timeout_seconds: float, environment: Mapping[str, str]
) -> subprocess.CompletedProcess[str]:
    if not command or command[0] != "docker":
        raise ImagePublicationError("publisher Docker command must start with the fixed docker executable token")
    executable = _resolve_docker_executable()
    argv = (executable, *command[1:])
    return subprocess.run(
        list(argv),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=dict(environment),
        timeout=timeout_seconds,
        check=False,
    )


def _run_compose_command(
    command: tuple[str, ...], cwd: str, timeout_seconds: float, environment: Mapping[str, str]
) -> subprocess.CompletedProcess[str]:
    return LocalBrokerHostMutations._run_compose(command, cwd, timeout_seconds, environment)


def _fetch_http(url: str, timeout_seconds: float) -> tuple[int, str]:
    request = Request(url, method="GET", headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            body = response.read(HEALTH_RESPONSE_LIMIT + 1)
            if len(body) > HEALTH_RESPONSE_LIMIT:
                raise ImagePublicationError("runtime health response exceeds its bounded size")
            return int(response.status), body.decode("utf-8", errors="replace")
    except HTTPError as exc:
        body = exc.read(HEALTH_RESPONSE_LIMIT + 1)
        if len(body) > HEALTH_RESPONSE_LIMIT:
            body = body[:HEALTH_RESPONSE_LIMIT]
        return int(exc.code), body.decode("utf-8", errors="replace")
    except (URLError, OSError) as exc:
        raise ImagePublicationError("runtime health endpoint is unreachable") from exc


def _wait_for_ready(
    url: str,
    timeout_seconds: int,
    fetcher: Callable[[str, float], tuple[int, str]],
    now: Callable[[], float],
) -> None:
    status, _body = _wait_for_http(url, timeout_seconds, fetcher, now, require_body=False)
    if status != 200:
        raise ImagePublicationError("published worker readiness endpoint did not return HTTP 200")


def _wait_for_http(
    url: str,
    timeout_seconds: int,
    fetcher: Callable[[str, float], tuple[int, str]],
    now: Callable[[], float],
    *,
    require_body: bool,
) -> tuple[int, str]:
    deadline = now() + timeout_seconds
    last_error: BaseException | None = None
    last_result: tuple[int, str] | None = None
    while now() <= deadline:
        try:
            result = fetcher(url, min(5.0, max(0.25, deadline - now())))
            if not isinstance(result, tuple) or len(result) != 2 or type(result[0]) is not int or not isinstance(result[1], str):
                raise ImagePublicationError("runtime health fetcher returned invalid evidence")
            last_result = result
            if result[0] == 200 and (not require_body or result[1]):
                return result
        except BaseException as exc:
            last_error = exc
        if now() >= deadline:
            break
        time.sleep(0.5)
    if last_error is not None:
        raise ImagePublicationError("runtime health endpoint did not become reachable") from last_error
    if last_result is not None:
        return last_result
    raise ImagePublicationError("runtime health endpoint produced no evidence")


def _nested_value(value: Any, parts: Sequence[str]) -> Any:
    current = value
    for part in parts:
        if not isinstance(current, Mapping):
            return None
        current = current.get(part)
    return current


def _require_canonical_operation_id(value: str) -> None:
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError) as exc:
        raise ImagePublicationError("publication operation ID must be a canonical UUID") from exc
    if str(parsed) != value:
        raise ImagePublicationError("publication operation ID must be a canonical UUID")


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
