"""Crash-safe broker ownership for administrator-sealed ephemeral containers.

The durable run and its unguessable creation nonce are committed before Docker
is invoked.  Docker is asked to create a stopped container carrying the exact
persisted identity.  The immutable container ID is then recorded before start.
If a process dies in either gap, recovery searches by all persisted labels and
can safely complete attribution after creation without guessing from a name.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import threading
import time
from typing import Any, Mapping
import uuid

from .broker import (
    AcceptedBrokerRequest,
    BrokerBackendError,
    BrokerError,
    BrokerOperation,
)
from .broker_host import (
    EphemeralDockerContainerTarget,
    EphemeralDockerCreateTarget,
    EphemeralDockerIdentity,
)
from .broker_persistence import (
    BrokerPersistence,
    DurableOperationDisposition,
    EphemeralContainerTarget,
    _validate_connection_request,
    _finish_operation,
    _normalize_ephemeral_image_cache_proof,
)
from .ephemeral_secrets import (
    EphemeralSecretError,
    EphemeralSecretMaterial,
    EphemeralSecretMount,
    EphemeralSecretPolicy,
    VolatileRunSecretManager,
)
from .store import fingerprint, utc_timestamp


_LOGGER = logging.getLogger(__name__)
_FULL_CONTAINER_ID = re.compile(r"[0-9a-f]{64}")
_ACTIVE_RUN_STATES = frozenset(
    {
        "reserved",
        "creating",
        "attributed",
        "starting",
        "running",
        "cleanup_pending",
        "stopping",
        "removing",
        "needs_attention",
    }
)
_ACTIVE_RUN_STATES_ORDERED = tuple(sorted(_ACTIVE_RUN_STATES))
_DEFAULT_EPHEMERAL_MEMORY_BYTES = 512 * 1024 * 1024
_DEFAULT_EPHEMERAL_CPU_MILLIS = 1000
# This service hard ceiling cannot be raised by a client request or repository
# manifest.  Repository and template limits normally stop admission first; the
# host ceiling remains a final guard when many independently configured
# repositories are active at once or older state was provisioned too loosely.
_HOST_MAX_ACTIVE_EPHEMERAL_RUNS = 128
_STARTUP_RECOVERY_BATCH_LIMIT = 4
_MAX_EPHEMERAL_PHASE_HISTORY = 256
_NON_TERMINAL_OPERATION_ERRORS = frozenset(
    {"operation_in_progress", "operation_outcome_uncertain", "service_shutting_down"}
)
_START_CLEANUP_FAILURE_CODES = frozenset(
    {
        "ephemeral_start_deadline_expired",
        "ephemeral_start_no_longer_permitted",
        "ephemeral_docker_safety_profile_mismatch",
    }
)
_RECOVERY_PROFILE_CLEANUP_FAILURE_CODES = frozenset(
    {
        "ephemeral_docker_safety_profile_mismatch",
        "ephemeral_image_inspect_unobservable",
    }
)
_START_CLEANUP_RESULT_CODES = (
    _START_CLEANUP_FAILURE_CODES
    | frozenset({"ephemeral_image_inspect_unobservable"})
)


class EphemeralSecretDeliveryLease:
    """One consumed credential held behind the coordinator mutation boundary.

    The lease is intentionally opaque to transport callers.  Its sole lifecycle
    effect is releasing the coordinator lock after the local descriptor has
    been closed, so Finish, Renew, and reaping cannot invalidate an accepted
    one-shot descriptor while it is still being sent.
    """

    def __init__(
        self,
        *,
        material: EphemeralSecretMaterial,
        mutation_lock: Any,
    ) -> None:
        self.material = material
        self._mutation_lock = mutation_lock
        self._close_lock = threading.Lock()
        self._closed = False

    def close(self) -> None:
        with self._close_lock:
            if self._closed:
                return
            self._mutation_lock.release()
            self._closed = True


class EphemeralContainerCoordinator:
    """Own the durable run state machine and exact typed Docker calls."""

    def __init__(
        self,
        persistence: BrokerPersistence,
        host: Any,
        *,
        secret_manager: VolatileRunSecretManager | None = None,
        reaper_interval_seconds: float = 15.0,
        clock: Any = time.time,
    ) -> None:
        if reaper_interval_seconds <= 0:
            raise ValueError("ephemeral reaper interval must be positive")
        self._persistence = persistence
        self._host = host
        self._secret_manager = secret_manager
        self._clock = clock
        self._reaper_interval_seconds = float(reaper_interval_seconds)
        self._mutation_lock = threading.RLock()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None

    def execute(self, accepted: AcceptedBrokerRequest) -> Mapping[str, Any]:
        request = accepted.request
        operation = request.operation
        if operation is BrokerOperation.EPHEMERAL_STATUS:
            return self._status(accepted)
        if operation is BrokerOperation.EPHEMERAL_IMAGE_STATUS:
            target = self._persistence.ephemeral_image_target(accepted)
            return self._host.docker_inspect_ephemeral_image(target)
        if operation not in {
            BrokerOperation.EPHEMERAL_START,
            BrokerOperation.EPHEMERAL_IMAGE_PREFETCH,
            BrokerOperation.EPHEMERAL_RENEW,
            BrokerOperation.EPHEMERAL_FINISH,
        }:
            raise BrokerBackendError(
                "unknown_operation",
                "Requested broker operation is not an ephemeral-container operation.",
                operation_id=accepted.request.operation_id,
            )
        with self._mutation_lock:
            disposition = self._persistence.reserve_operation(accepted)
            replay = (
                self._resolve_image_prefetch_disposition(accepted, disposition)
                if operation is BrokerOperation.EPHEMERAL_IMAGE_PREFETCH
                else self._resolve_disposition(accepted, disposition)
            )
            if replay is not None:
                return replay
            try:
                if operation is BrokerOperation.EPHEMERAL_START:
                    return self._start(accepted)
                if operation is BrokerOperation.EPHEMERAL_IMAGE_PREFETCH:
                    return self._prefetch_image(accepted)
                if operation is BrokerOperation.EPHEMERAL_RENEW:
                    return self._renew(accepted)
                return self._finish(accepted)
            except BrokerError as error:
                self._terminalize_reserved_start_before_host(
                    request,
                    code=error.code,
                    message=error.message,
                )
                if error.code == "ephemeral_lease_invariant_failed":
                    self._mark_attention(
                        request.resource_id,
                        phase="lease_invariant_failed",
                        code=error.code,
                        message=error.message,
                    )
                    self._wake.set()
                if error.code not in _NON_TERMINAL_OPERATION_ERRORS:
                    self._finish_reserved_error(
                        request.operation_id,
                        code=error.code,
                        message=error.message,
                    )
                raise
            except Exception as error:
                self._terminalize_reserved_start_before_host(
                    request,
                    code="ephemeral_operation_failed",
                    message=(
                        "The broker rejected the ephemeral-container operation "
                        "before a host outcome became uncertain."
                    ),
                )
                self._finish_reserved_error(
                    request.operation_id,
                    code="ephemeral_operation_failed",
                    message=(
                        "The broker rejected the ephemeral-container operation "
                        "before a host outcome became uncertain."
                    ),
                )
                raise BrokerBackendError(
                    "ephemeral_operation_failed",
                    "The broker rejected the ephemeral-container operation before invoking an uncertain host mutation.",
                    operation_id=request.operation_id,
                ) from error

    def acquire_secret_fd_delivery(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        template_id: str,
        run_id: uuid.UUID,
        request_id: uuid.UUID,
    ) -> EphemeralSecretDeliveryLease:
        """Consume one descriptor payload while blocking all run mutations.

        The caller must close the returned lease only after its local copy of
        the descriptor is closed. This spans exact durable run validation,
        volatile one-time consumption, and Unix descriptor transmission.
        """

        self._mutation_lock.acquire()
        try:
            target = self._persistence.ephemeral_secret_fd_target(
                accepted,
                template_id=template_id,
                run_id=run_id,
            )
            material = self._require_secret_manager().consume_run_secret(
                peer_uid=target.owner_uid,
                account_id=target.account_id,
                repository_id=target.repo_id,
                template_id=target.template_id,
                run_id=run_id,
                request_id=request_id,
            )
        except BaseException:
            self._mutation_lock.release()
            raise
        return EphemeralSecretDeliveryLease(
            material=material,
            mutation_lock=self._mutation_lock,
        )

    def recover_startup(self) -> dict[str, Any]:
        """Fence every unproven credential run, then reconcile one bounded batch.

        The Docker half of startup recovery is deliberately bounded so one
        unavailable engine cannot hold the Unix socket closed indefinitely.
        That bound must *not* leave a policy-backed PostgreSQL run advertised
        as usable merely because it fell after the first four rows.  Before
        socket admission, prove each live policy run's volatile material (or
        durably fence it for cleanup) without invoking Docker.  Only the
        subsequent host reconciliation remains batch-bounded.
        """

        recovered: list[str] = []
        attention: list[str] = []
        policy_material_fenced: list[str] = []
        with self._mutation_lock:
            policy_material_fenced = self._preflight_policy_material_before_admission()
            total_active = self._active_recovery_count()
            targets = self._recovery_targets(
                limit=_STARTUP_RECOVERY_BATCH_LIMIT
            )
            for target in targets:
                try:
                    self._recover_target(target)
                    recovered.append(target.run_id)
                except Exception:
                    attention.append(target.run_id)
                    self._mark_attention(
                        target.run_id,
                        phase="startup_recovery",
                        code="ephemeral_recovery_failed",
                        message=(
                            "The broker could not reconcile this ephemeral run; "
                            "inspect service logs and retry recovery."
                        ),
                    )
                    _LOGGER.exception(
                        "ephemeral startup recovery failed for run %s", target.run_id
                    )
        return {
            "recovered": len(recovered),
            "attention": len(attention),
            "deferred": max(0, total_active - len(targets)),
            "batch_limit": _STARTUP_RECOVERY_BATCH_LIMIT,
            "run_ids": recovered,
            "attention_run_ids": attention,
            "policy_material_fenced": len(policy_material_fenced),
            "policy_material_fenced_run_ids": policy_material_fenced,
        }

    def _preflight_policy_material_before_admission(self) -> list[str]:
        """Fence all live policy runs whose volatile material is not provable.

        This stage intentionally makes no Docker call.  A process restart can
        preserve the durable SQLite record while a host reboot has erased
        ``/run``.  Fencing the durable row first prevents a fifth (or later)
        live run from leaking through status or inventory as ``running`` while
        waiting for the bounded Docker recovery batch/reaper.

        A persistence failure is allowed to escape: admitting the socket with
        an unfenced policy run would be less safe than refusing startup.
        """

        fenced: list[str] = []
        for target in self._policy_recovery_targets():
            if target.cleanup_requested:
                self._cancel_renewal_for_cleanup(target)
                continue
            if self._policy_material_is_proven(target):
                continue
            message = (
                "The broker cannot prove volatile PostgreSQL credential material "
                "for this recovered ephemeral run."
            )
            fenced_target = self._persist_cleanup_intent(
                target.run_id,
                reason=message,
                code="secret_delivery_unavailable",
                message=message,
            )
            self._cancel_renewal_for_cleanup(fenced_target)
            fenced.append(target.run_id)
        return fenced

    def _policy_material_is_proven(self, target: EphemeralContainerTarget) -> bool:
        """Return whether one policy run has exact usable volatile material.

        Interrupted expiry renewal journals use their narrower inspection
        contract because a normal mount correctly rejects unresolved renewal
        state.  Any unexpected state is deliberately treated as unproven and
        is cleanup-fenced before a client can connect.
        """

        if target.secret_policy is None:
            return True
        try:
            if target.credential_renewal_phase == "none":
                self._secret_mount_for_target(target, require_material=True)
                return True
            old_expiry = target.credential_renewal_old_expires_at_epoch
            new_expiry = target.credential_renewal_new_expires_at_epoch
            if (
                target.credential_renewal_phase not in {"prepared", "committing"}
                or old_expiry is None
                or new_expiry is None
                or target.credential_renewal_operation_id is None
            ):
                return False
            observed = self._inspect_secret_expiry_renewal(
                target,
                new_expires_at_epoch=new_expiry,
            )
        except BrokerError:
            return False
        if target.credential_renewal_phase == "prepared":
            return observed in {"old", "prepared"}
        return observed in {"prepared", "new"}

    def start_reaper(self) -> None:
        if self._thread is not None or self._stop.is_set():
            return
        self._thread = threading.Thread(
            target=self._reaper_loop,
            name="devcoordinator-ephemeral-reaper",
            daemon=True,
        )
        self._thread.start()

    def request_reaper_stop(self) -> None:
        """Ask the reaper to stop without waiting for in-flight host work.

        The broker calls this from its signal-turn shutdown fence.  Docker
        mutations are bounded but may still be in progress, so joining here
        would make signal handling wait on a host subprocess and would spend a
        hidden ten-second deadline before the broker's real drain deadline is
        established.
        """

        self._stop.set()
        self._wake.set()

    def wait_reaper_stopped(self, timeout_seconds: float) -> None:
        """Join the requested reaper within the caller-owned drain deadline."""

        if timeout_seconds < 0:
            raise ValueError("timeout_seconds must be non-negative")
        thread = self._thread
        if thread is None:
            return
        thread.join(timeout_seconds)
        if thread.is_alive():
            raise BrokerBackendError(
                "ephemeral_reaper_shutdown_timeout",
                "The ephemeral-container reaper did not stop before shutdown.",
            )
        self._thread = None

    def stop_reaper(self, timeout_seconds: float = 10.0) -> None:
        """Compatibility helper for non-signal callers."""

        self.request_reaper_stop()
        self.wait_reaper_stopped(timeout_seconds)

    def reap_once(self) -> dict[str, Any]:
        now = int(self._clock())
        cleaned: list[str] = []
        attention: list[str] = []
        with self._mutation_lock:
            for target in self._recovery_targets(due_before=now):
                # A single pass is bounded by row count, but each row can
                # include a bounded Docker host call.  Once shutdown has been
                # requested, finish only the current call and do not begin the
                # next target; otherwise a full batch could consume many host
                # timeouts and exceed the broker-wide drain deadline.
                if self._stop.is_set():
                    break
                try:
                    self._recover_target(target)
                    cleaned.append(target.run_id)
                except Exception:
                    attention.append(target.run_id)
                    self._mark_attention(
                        target.run_id,
                        phase="reaper_recovery",
                        code="ephemeral_recovery_failed",
                        message=(
                            "The broker could not reconcile this ephemeral run; "
                            "inspect service logs and retry recovery."
                        ),
                    )
                    _LOGGER.exception(
                        "ephemeral reaper failed for run %s", target.run_id
                    )
        return {
            "processed": len(cleaned),
            "attention": len(attention),
            "run_ids": cleaned,
            "attention_run_ids": attention,
        }

    def _reaper_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.reap_once()
            except Exception:
                _LOGGER.exception("ephemeral reaper iteration failed")
            self._wake.wait(self._reaper_interval_seconds)
            self._wake.clear()

    def _resolve_disposition(
        self,
        accepted: AcceptedBrokerRequest,
        disposition: DurableOperationDisposition,
    ) -> dict[str, Any] | None:
        if disposition.state == "completed":
            return dict(disposition.result or {})
        if disposition.state == "failed":
            raise BrokerBackendError(
                disposition.error_code or "mutation_failed",
                disposition.error_message or "Ephemeral-container operation failed.",
                operation_id=accepted.request.operation_id,
            )
        if disposition.state == "execute":
            return None

        # A retry may be the first caller after an uncertain host result.  Try
        # exact nonce/label reconciliation once instead of blindly replaying.
        request = accepted.request
        run_id = (
            request.operation_id
            if request.operation is BrokerOperation.EPHEMERAL_START
            else request.resource_id
        )
        target = self._target_or_none(run_id)
        if target is not None:
            try:
                self._recover_target(target)
            except Exception:
                pass
        replay = self._persistence.existing_operation_disposition(accepted)
        if replay is not None and replay.state == "completed":
            return dict(replay.result or {})
        if replay is not None and replay.state == "failed":
            raise BrokerBackendError(
                replay.error_code or "mutation_failed",
                replay.error_message or "Ephemeral-container operation failed.",
                operation_id=request.operation_id,
            )
        raise BrokerBackendError(
            "operation_in_progress",
            "This ephemeral-container operation is still being reconciled; retry it with the same operation ID.",
            operation_id=request.operation_id,
        )

    def _resolve_image_prefetch_disposition(
        self,
        accepted: AcceptedBrokerRequest,
        disposition: DurableOperationDisposition,
    ) -> dict[str, Any] | None:
        """Reconcile a pending pull only by exact local proof, never another pull."""

        if disposition.state == "completed":
            return dict(disposition.result or {})
        if disposition.state == "failed":
            raise BrokerBackendError(
                disposition.error_code or "mutation_failed",
                disposition.error_message or "Ephemeral image prefetch failed.",
                operation_id=accepted.request.operation_id,
            )
        if disposition.state == "execute":
            return None
        target = self._persistence.ephemeral_image_target(
            accepted, require_reserved_operation=True
        )
        try:
            proof = self._host.docker_inspect_ephemeral_image(target)
        except BrokerBackendError as error:
            raise BrokerBackendError(
                "operation_outcome_uncertain",
                "The prior sealed image prefetch cannot yet be reconciled; retry with the same operation ID.",
                operation_id=accepted.request.operation_id,
            ) from error
        if proof.get("cached") is True:
            return self._persistence.complete_ephemeral_image_prefetch(
                accepted,
                target=target,
                proof=proof,
                cache_origin="reconciled",
                changed=None,
            )
        raise BrokerBackendError(
            "operation_outcome_uncertain",
            "The prior sealed image prefetch has no exact cache proof yet; it was not replayed.",
            operation_id=accepted.request.operation_id,
        )

    def _prefetch_image(self, accepted: AcceptedBrokerRequest) -> dict[str, Any]:
        """Perform one explicit sealed image prefetch after durable reservation."""

        target = self._persistence.ephemeral_image_target(
            accepted, require_reserved_operation=True
        )
        outcome = self._host.docker_prefetch_ephemeral_image(target)
        cache_origin = outcome.get("cache_origin")
        changed = outcome.get("changed")
        if not isinstance(cache_origin, str) or changed is not None and type(changed) is not bool:
            raise BrokerBackendError(
                "ephemeral_image_inspect_unobservable",
                "The service did not return complete sealed image cache evidence.",
                operation_id=accepted.request.operation_id,
            )
        proof = {
            key: outcome.get(key)
            for key in (
                "cached",
                "image_ref",
                "image_id",
                "repo_digest",
                "os",
                "architecture",
            )
        }
        return self._persistence.complete_ephemeral_image_prefetch(
            accepted,
            target=target,
            proof=proof,
            cache_origin=cache_origin,
            changed=changed,
        )

    def _start(self, accepted: AcceptedBrokerRequest) -> dict[str, Any]:
        request = accepted.request
        image_target = self._persistence.ephemeral_image_target(
            accepted, require_reserved_operation=True
        )
        cache_proof = self._host.docker_inspect_ephemeral_image(image_target)
        if cache_proof.get("cached") is not True:
            raise BrokerBackendError(
                "ephemeral_image_not_cached",
                "The exact sealed image is not verified in the local cache; use the accepted image-prefetch action first.",
                operation_id=request.operation_id,
            )
        try:
            _normalize_ephemeral_image_cache_proof(
                cache_proof, target=image_target
            )
        except BrokerError as error:
            raise BrokerBackendError(
                error.code,
                error.message,
                operation_id=request.operation_id,
            ) from error
        target = self._prepare_start(
            accepted,
            expected_image_ref=image_target.image_ref,
            expected_template_fingerprint=image_target.template_fingerprint,
        )
        host_invoked = False
        try:
            secret_mount = self._provision_secret_for_start(target)
            if target.container_tcp_port is not None and target.host_port is None:
                candidates = self._port_candidates(accepted, target.run_id)
                selected = self._host.select_available_port(
                    candidates=candidates, protocol="tcp"
                )
                if selected is None:
                    self._fail_before_create(
                        target.run_id,
                        code="port_unavailable",
                        message="No accepted ephemeral host port is currently free.",
                    )
                    raise BrokerBackendError(
                        "port_unavailable",
                        "No accepted ephemeral host port is currently free.",
                        operation_id=request.operation_id,
                    )
                if type(selected) is not int or selected not in candidates:
                    self._fail_before_create(
                        target.run_id,
                        code="invalid_host_observation",
                        message="The host port observer returned a candidate outside the accepted range.",
                    )
                    raise BrokerBackendError(
                        "invalid_host_observation",
                        "The host port observer returned a candidate outside the accepted range.",
                        operation_id=request.operation_id,
                    )
                target = self._bind_port(accepted, target.run_id, selected)

            self._transition(
                target.run_id,
                expected={"reserved"},
                status="creating",
                phase="docker_create_invoked",
            )
            host_invoked = True
            created = self._host.docker_create_ephemeral(
                self._create_target(target, secret_mount=secret_mount)
            )
            full_id = _full_id(created.get("full_container_id"))
            target = self._record_container(
                target.run_id, full_id, accepted=accepted
            )
            if int(self._clock()) >= target.expires_at_epoch:
                code = "ephemeral_start_deadline_expired"
                message = (
                    "The ephemeral TTL elapsed before Docker start; the stopped "
                    "container was removed."
                )
                self._cleanup(
                    target,
                    operation_id=None,
                    reason=message,
                    code=code,
                    message=message,
                )
                raise BrokerBackendError(
                    code,
                    message,
                    operation_id=request.operation_id,
                )
            if not self._recovery_start_permitted(target):
                code = "ephemeral_start_no_longer_permitted"
                message = (
                    "The template or repository became unavailable before Docker start; "
                    "the stopped container was removed."
                )
                self._cleanup(
                    target,
                    operation_id=None,
                    reason=message,
                    code=code,
                    message=message,
                )
                raise BrokerBackendError(
                    code,
                    message,
                    operation_id=request.operation_id,
                )
            self._transition(
                target.run_id,
                expected={"attributed"},
                status="starting",
                phase="docker_start_invoked",
            )
            started = self._host.docker_start_ephemeral(
                self._container_target(target, require_material=True)
            )
            result = self._complete_running(
                accepted, target.run_id, host_result=started
            )
            self._wake.set()
            return result
        except BrokerError as error:
            if not host_invoked or error.code in _START_CLEANUP_FAILURE_CODES:
                raise
            self._mark_attention(
                target.run_id,
                phase="start_outcome_uncertain",
                code="operation_outcome_uncertain",
                message=(
                    "Docker may have accepted the ephemeral create/start; "
                    "the persisted nonce will be reconciled before any retry."
                ),
            )
            self._wake.set()
            raise BrokerBackendError(
                "operation_outcome_uncertain",
                "Docker may have accepted the ephemeral create/start; exact persisted-label reconciliation is required.",
                operation_id=request.operation_id,
            ) from error
        except Exception as error:
            if not host_invoked:
                raise
            self._mark_attention(
                target.run_id,
                phase="start_outcome_uncertain",
                code="operation_outcome_uncertain",
                message=(
                    "Docker may have accepted the ephemeral create/start; "
                    "the persisted nonce will be reconciled before any retry."
                ),
            )
            self._wake.set()
            raise BrokerBackendError(
                "operation_outcome_uncertain",
                "Docker may have accepted the ephemeral create/start; exact persisted-label reconciliation is required.",
                operation_id=request.operation_id,
            ) from error

    def _renew(self, accepted: AcceptedBrokerRequest) -> dict[str, Any]:
        """Renew through a durable DB/file transition, never a silent mismatch."""

        request = accepted.request
        now_epoch = int(self._clock())
        ttl = int(request.arguments["ttl_seconds"])
        target, new_expiry = self._prepare_renewal_journal(
            accepted,
            ttl_seconds=ttl,
            now_epoch=now_epoch,
        )
        self._renewal_checkpoint("durable_prepared")
        try:
            self._prepare_secret_expiry_renewal(
                target,
                new_expires_at_epoch=new_expiry,
                now_epoch=now_epoch,
            )
        except Exception as error:
            self._renewal_uncertain(
                target,
                phase="credential_renewal_prepare_uncertain",
                message=(
                    "The broker could not prove the volatile credential expiry "
                    "transition; recovery will reconcile or clean this run."
                ),
            )
            raise BrokerBackendError(
                "operation_outcome_uncertain",
                "Ephemeral credential renewal needs recovery before it can be retried.",
                operation_id=request.operation_id,
            ) from error
        self._renewal_checkpoint("volatile_prepared")
        try:
            committed = self._commit_renewal_journal(
                accepted,
                target,
                new_expires_at_epoch=new_expiry,
                now_epoch=now_epoch,
            )
        except Exception as error:
            self._renewal_uncertain(
                target,
                phase="credential_renewal_commit_uncertain",
                message=(
                    "The broker could not durably commit the renewal boundary; "
                    "recovery will reconcile or clean this run."
                ),
            )
            raise BrokerBackendError(
                "operation_outcome_uncertain",
                "Ephemeral credential renewal needs recovery before it can be retried.",
                operation_id=request.operation_id,
            ) from error
        self._renewal_checkpoint("durable_committing")
        try:
            self._commit_secret_expiry_renewal(
                target,
                new_expires_at_epoch=new_expiry,
                now_epoch=now_epoch,
            )
        except Exception as error:
            self._renewal_uncertain(
                committed,
                phase="credential_renewal_material_commit_uncertain",
                message=(
                    "The broker could not prove the volatile credential expiry "
                    "commit; recovery will reconcile or clean this run."
                ),
            )
            raise BrokerBackendError(
                "operation_outcome_uncertain",
                "Ephemeral credential renewal needs recovery before it can be retried.",
                operation_id=request.operation_id,
            ) from error
        self._renewal_checkpoint("volatile_committed")
        try:
            result = self._finalize_renewal(
                committed,
                operation_id=request.operation_id,
                now_epoch=now_epoch,
            )
        except Exception as error:
            self._renewal_uncertain(
                committed,
                phase="credential_renewal_finalize_uncertain",
                message=(
                    "The broker could not publish the committed renewal outcome; "
                    "recovery will reconcile it exactly once."
                ),
            )
            raise BrokerBackendError(
                "operation_outcome_uncertain",
                "Ephemeral credential renewal needs recovery before it can be retried.",
                operation_id=request.operation_id,
            ) from error
        self._wake.set()
        return result

    def _prepare_renewal_journal(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        ttl_seconds: int,
        now_epoch: int,
    ) -> tuple[EphemeralContainerTarget, int]:
        request = accepted.request
        now = utc_timestamp(now_epoch)
        with self._persistence._store() as store:
            with store.immediate_transaction() as connection:
                _validate_connection_request(connection, peer=accepted.peer, request=request)
                target = _target(connection, request.resource_id)
                if ttl_seconds > target.max_ttl_seconds:
                    raise BrokerError(
                        "ttl_policy_denied",
                        "Requested TTL exceeds the administrator-sealed template policy.",
                        operation_id=request.operation_id,
                    )
                if target.status != "running":
                    raise BrokerError(
                        "ephemeral_run_not_running",
                        "Only a running ephemeral container can be renewed.",
                        operation_id=request.operation_id,
                    )
                if target.credential_renewal_phase != "none":
                    raise BrokerError(
                        "operation_outcome_uncertain",
                        "A prior ephemeral credential renewal still needs recovery.",
                        operation_id=request.operation_id,
                    )
                if now_epoch >= target.expires_at_epoch:
                    raise BrokerError(
                        "ephemeral_run_expired",
                        "The ephemeral run has reached its cleanup deadline and cannot be renewed.",
                        operation_id=request.operation_id,
                    )
                self._require_renewal_lease(
                    connection,
                    target,
                    operation_id=request.operation_id,
                )
                new_expiry = now_epoch + ttl_seconds
                if new_expiry == target.expires_at_epoch:
                    raise BrokerError(
                        "ttl_policy_denied",
                        "Requested TTL does not change the ephemeral expiration.",
                        operation_id=request.operation_id,
                    )
                cursor = connection.execute(
                    """
                    UPDATE ephemeral_container_runs
                    SET credential_renewal_phase = 'prepared',
                        credential_renewal_old_expires_at_epoch = ?,
                        credential_renewal_new_expires_at_epoch = ?,
                        credential_renewal_operation_id = ?,
                        phase = 'credential_renewal_prepared',
                        generation = generation + 1, updated_at = ?
                    WHERE run_id = ? AND status = 'running'
                      AND credential_renewal_phase = 'none'
                      AND expires_at_epoch = ?
                    """,
                    (
                        target.expires_at_epoch,
                        new_expiry,
                        request.operation_id,
                        now,
                        target.run_id,
                        target.expires_at_epoch,
                    ),
                )
                if cursor.rowcount != 1:
                    raise BrokerError(
                        "operation_state_conflict",
                        "Ephemeral renewal changed before its durable transition began.",
                        operation_id=request.operation_id,
                    )
                _phase(
                    connection,
                    run_id=target.run_id,
                    phase="credential_renewal_prepared",
                    status="running",
                    evidence={
                        "old_expires_at_epoch": target.expires_at_epoch,
                        "new_expires_at_epoch": new_expiry,
                    },
                    recorded_at=now,
                )
                return _target(connection, target.run_id), new_expiry

    def _commit_renewal_journal(
        self,
        accepted: AcceptedBrokerRequest,
        target: EphemeralContainerTarget,
        *,
        new_expires_at_epoch: int,
        now_epoch: int,
    ) -> EphemeralContainerTarget:
        request = accepted.request
        old_expiry = target.expires_at_epoch
        now = utc_timestamp(now_epoch)
        with self._persistence._store() as store:
            with store.immediate_transaction() as connection:
                _validate_connection_request(connection, peer=accepted.peer, request=request)
                current = _target(connection, target.run_id)
                self._require_renewal_transition(
                    current,
                    phase="prepared",
                    old_expires_at_epoch=old_expiry,
                    new_expires_at_epoch=new_expires_at_epoch,
                    operation_id=request.operation_id,
                )
                if current.status != "running":
                    raise BrokerError(
                        "operation_state_conflict",
                        "Ephemeral run changed before the credential renewal commit.",
                        operation_id=request.operation_id,
                    )
                self._require_renewal_lease(
                    connection,
                    current,
                    operation_id=request.operation_id,
                )
                cursor = connection.execute(
                    """
                    UPDATE ephemeral_container_runs
                    SET expires_at_epoch = ?, credential_renewal_phase = 'committing',
                        phase = 'credential_renewal_committing',
                        generation = generation + 1, updated_at = ?
                    WHERE run_id = ? AND status = 'running'
                      AND credential_renewal_phase = 'prepared'
                      AND credential_renewal_old_expires_at_epoch = ?
                      AND credential_renewal_new_expires_at_epoch = ?
                      AND credential_renewal_operation_id = ?
                      AND expires_at_epoch = ?
                    """,
                    (
                        new_expires_at_epoch,
                        now,
                        current.run_id,
                        old_expiry,
                        new_expires_at_epoch,
                        request.operation_id,
                        old_expiry,
                    ),
                )
                if cursor.rowcount != 1:
                    raise BrokerError(
                        "operation_state_conflict",
                        "Ephemeral renewal changed before the credential commit.",
                        operation_id=request.operation_id,
                    )
                if current.lease_id is not None:
                    cursor = connection.execute(
                        """
                        UPDATE leases SET expires_at = ?, updated_at = ?,
                            generation = generation + 1
                        WHERE lease_id = ? AND status = 'active'
                        """,
                        (
                            utc_timestamp(new_expires_at_epoch),
                            now,
                            current.lease_id,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise BrokerError(
                            "ephemeral_lease_invariant_failed",
                            "The published ephemeral run no longer owns its exact active port lease.",
                            operation_id=request.operation_id,
                        )
                _phase(
                    connection,
                    run_id=current.run_id,
                    phase="credential_renewal_committing",
                    status="running",
                    evidence={"expires_at_epoch": new_expires_at_epoch},
                    recorded_at=now,
                )
                return _target(connection, current.run_id)


    def _finalize_renewal(
        self,
        target: EphemeralContainerTarget,
        *,
        operation_id: str,
        now_epoch: int,
    ) -> dict[str, Any]:
        old_expiry = target.credential_renewal_old_expires_at_epoch
        new_expiry = target.credential_renewal_new_expires_at_epoch
        if old_expiry is None or new_expiry is None:
            raise BrokerError(
                "operation_state_conflict",
                "Ephemeral renewal journal is incomplete.",
                operation_id=operation_id,
            )
        now = utc_timestamp(now_epoch)
        with self._persistence._store() as store:
            with store.immediate_transaction() as connection:
                current = _target(connection, target.run_id)
                self._require_renewal_transition(
                    current,
                    phase="committing",
                    old_expires_at_epoch=old_expiry,
                    new_expires_at_epoch=new_expiry,
                    operation_id=operation_id,
                )
                if current.expires_at_epoch != new_expiry:
                    raise BrokerError(
                        "operation_state_conflict",
                        "Ephemeral renewal expiry no longer matches its commit journal.",
                        operation_id=operation_id,
                    )
                self._require_renewal_operation(
                    connection,
                    current,
                    operation_id=operation_id,
                )
                connection.execute(
                    """
                    UPDATE ephemeral_container_runs
                    SET status = 'running', phase = 'lease_renewed',
                        credential_renewal_phase = 'none',
                        credential_renewal_old_expires_at_epoch = NULL,
                        credential_renewal_new_expires_at_epoch = NULL,
                        credential_renewal_operation_id = NULL,
                        next_reconcile_at_epoch = ?, recovery_failures = 0,
                        error_code = NULL, error_message = NULL,
                        generation = generation + 1, updated_at = ?
                    WHERE run_id = ?
                    """,
                    (now_epoch + 60, now, current.run_id),
                )
                _phase(
                    connection,
                    run_id=current.run_id,
                    phase="lease_renewed",
                    status="succeeded",
                    evidence={"expires_at_epoch": new_expiry},
                    recorded_at=now,
                )
                result = {
                    **_public_target(_target(connection, current.run_id)),
                    "action": "renew",
                }
                _event(
                    connection,
                    run_id=current.run_id,
                    repo_id=current.repo_id,
                    operation_id=operation_id,
                    event_kind="ephemeral.renewed",
                    code="ephemeral_renewed",
                    message=f"Ephemeral container {current.container_name} was renewed",
                    diagnostic={"expires_at_epoch": new_expiry},
                    occurred_at=now,
                )
                _finish_operation(connection, operation_id, result=result)
                return result

    def _cancel_prepared_renewal(
        self,
        target: EphemeralContainerTarget,
        *,
        operation_id: str,
        now_epoch: int,
    ) -> EphemeralContainerTarget:
        old_expiry = target.credential_renewal_old_expires_at_epoch
        new_expiry = target.credential_renewal_new_expires_at_epoch
        if old_expiry is None or new_expiry is None:
            raise BrokerError(
                "operation_state_conflict",
                "Ephemeral renewal journal is incomplete.",
                operation_id=operation_id,
            )
        now = utc_timestamp(now_epoch)
        with self._persistence._store() as store:
            with store.immediate_transaction() as connection:
                current = _target(connection, target.run_id)
                self._require_renewal_transition(
                    current,
                    phase="prepared",
                    old_expires_at_epoch=old_expiry,
                    new_expires_at_epoch=new_expiry,
                    operation_id=operation_id,
                )
                if current.expires_at_epoch != old_expiry:
                    raise BrokerError(
                        "operation_state_conflict",
                        "Ephemeral renewal rollback no longer has its old expiry.",
                        operation_id=operation_id,
                    )
                self._require_renewal_operation(
                    connection,
                    current,
                    operation_id=operation_id,
                )
                connection.execute(
                    """
                    UPDATE ephemeral_container_runs
                    SET status = 'running', phase = 'credential_renewal_interrupted',
                        credential_renewal_phase = 'none',
                        credential_renewal_old_expires_at_epoch = NULL,
                        credential_renewal_new_expires_at_epoch = NULL,
                        credential_renewal_operation_id = NULL,
                        generation = generation + 1, updated_at = ?
                    WHERE run_id = ?
                    """,
                    (now, current.run_id),
                )
                _phase(
                    connection,
                    run_id=current.run_id,
                    phase="credential_renewal_interrupted",
                    status="failed",
                    error={
                        "code": "ephemeral_renewal_interrupted",
                        "message": (
                            "A broker restart interrupted the credential renewal "
                            "before commit."
                        ),
                    },
                    recorded_at=now,
                )
                operation = connection.execute(
                    "SELECT status FROM operations WHERE operation_id = ?",
                    (operation_id,),
                ).fetchone()
                if operation is not None and str(operation["status"]) == "running":
                    _finish_operation(
                        connection,
                        operation_id,
                        error_code="ephemeral_renewal_interrupted",
                        error_message=(
                            "The credential renewal was interrupted before its "
                            "durable commit and was rolled back."
                        ),
                    )
                return _target(connection, current.run_id)

    def _require_renewal_transition(
        self,
        target: EphemeralContainerTarget,
        *,
        phase: str,
        old_expires_at_epoch: int,
        new_expires_at_epoch: int,
        operation_id: str,
    ) -> None:
        if (
            target.credential_renewal_phase != phase
            or target.credential_renewal_old_expires_at_epoch != old_expires_at_epoch
            or target.credential_renewal_new_expires_at_epoch != new_expires_at_epoch
            or target.credential_renewal_operation_id != operation_id
        ):
            raise BrokerError(
                "operation_state_conflict",
                "Ephemeral credential renewal journal changed unexpectedly.",
                operation_id=operation_id,
            )

    def _require_renewal_operation(
        self,
        connection: sqlite3.Connection,
        target: EphemeralContainerTarget,
        *,
        operation_id: str,
    ) -> None:
        row = connection.execute(
            """
            SELECT operation.status
            FROM operations operation
            JOIN broker_operation_requests request USING(operation_id)
            WHERE operation.operation_id = ? AND request.repo_id = ?
              AND request.resource_id = ? AND request.operation = ?
            """,
            (
                operation_id,
                target.repo_id,
                target.run_id,
                BrokerOperation.EPHEMERAL_RENEW.value,
            ),
        ).fetchone()
        if row is None or str(row["status"]) != "running":
            raise BrokerError(
                "operation_state_conflict",
                "Ephemeral renewal journal does not name its exact pending renewal operation.",
                operation_id=operation_id,
            )

    def _require_renewal_lease(
        self,
        connection: sqlite3.Connection,
        target: EphemeralContainerTarget,
        *,
        operation_id: str,
    ) -> None:
        if target.lease_id is None:
            return
        lease = connection.execute(
            """
            SELECT port FROM leases
            WHERE lease_id = ? AND repo_id = ? AND status = 'active'
            """,
            (target.lease_id, target.repo_id),
        ).fetchone()
        if (
            lease is None
            or target.host_port is None
            or int(lease["port"]) != target.host_port
        ):
            raise BrokerError(
                "ephemeral_lease_invariant_failed",
                "The published ephemeral run no longer owns its exact active port lease.",
                operation_id=operation_id,
            )


    def _prepare_secret_expiry_renewal(
        self,
        target: EphemeralContainerTarget,
        *,
        new_expires_at_epoch: int,
        now_epoch: int,
    ) -> None:
        if target.secret_policy is None:
            return
        old_expiry = (
            target.credential_renewal_old_expires_at_epoch
            if target.credential_renewal_old_expires_at_epoch is not None
            else target.expires_at_epoch
        )
        manager = self._require_secret_manager()
        try:
            manager.prepare_expiry_renewal(
                peer_uid=target.owner_uid,
                account_id=target.account_id,
                repository_id=target.repo_id,
                template_id=target.template_id,
                run_id=uuid.UUID(target.run_id),
                policy=target.secret_policy,
                old_expires_at_epoch=old_expiry,
                new_expires_at_epoch=new_expires_at_epoch,
                now_epoch=now_epoch,
            )
        except (EphemeralSecretError, TypeError, ValueError) as exc:
            raise BrokerError(
                "secret_delivery_unavailable",
                "The broker could not prepare the volatile credential renewal.",
            ) from exc

    def _commit_secret_expiry_renewal(
        self,
        target: EphemeralContainerTarget,
        *,
        new_expires_at_epoch: int,
        now_epoch: int,
    ) -> None:
        if target.secret_policy is None:
            return
        old_expiry = (
            target.credential_renewal_old_expires_at_epoch
            if target.credential_renewal_old_expires_at_epoch is not None
            else target.expires_at_epoch
        )

        manager = self._require_secret_manager()
        try:
            manager.commit_expiry_renewal(
                peer_uid=target.owner_uid,
                account_id=target.account_id,
                repository_id=target.repo_id,
                template_id=target.template_id,
                run_id=uuid.UUID(target.run_id),
                policy=target.secret_policy,
                old_expires_at_epoch=old_expiry,
                new_expires_at_epoch=new_expires_at_epoch,
                now_epoch=now_epoch,
            )
        except (EphemeralSecretError, TypeError, ValueError) as exc:
            raise BrokerError(
                "secret_delivery_unavailable",
                "The broker could not commit the volatile credential renewal.",
            ) from exc

    def _rollback_secret_expiry_renewal(
        self,
        target: EphemeralContainerTarget,
        *,
        new_expires_at_epoch: int,
    ) -> None:
        if target.secret_policy is None:
            return
        manager = self._require_secret_manager()
        try:
            manager.rollback_expiry_renewal(
                peer_uid=target.owner_uid,
                account_id=target.account_id,
                repository_id=target.repo_id,
                template_id=target.template_id,
                run_id=uuid.UUID(target.run_id),
                policy=target.secret_policy,
                old_expires_at_epoch=target.expires_at_epoch,
                new_expires_at_epoch=new_expires_at_epoch,
            )
        except (EphemeralSecretError, TypeError, ValueError) as exc:
            raise BrokerError(
                "secret_delivery_unavailable",
                "The broker could not roll back the volatile credential renewal.",
            ) from exc

    def _inspect_secret_expiry_renewal(
        self,
        target: EphemeralContainerTarget,
        *,
        new_expires_at_epoch: int,
    ) -> str:
        if target.secret_policy is None:
            return "no_secret"
        old_expiry = target.credential_renewal_old_expires_at_epoch
        if old_expiry is None:
            raise BrokerError(
                "operation_state_conflict",
                "Ephemeral renewal journal is incomplete.",
            )
        manager = self._require_secret_manager()
        try:
            return manager.inspect_expiry_renewal(
                peer_uid=target.owner_uid,
                account_id=target.account_id,
                repository_id=target.repo_id,
                template_id=target.template_id,
                run_id=uuid.UUID(target.run_id),
                policy=target.secret_policy,
                old_expires_at_epoch=old_expiry,
                new_expires_at_epoch=new_expires_at_epoch,
            )
        except (EphemeralSecretError, TypeError, ValueError) as exc:
            raise BrokerError(
                "secret_delivery_unavailable",
                "The broker could not inspect the volatile credential renewal.",
            ) from exc

    def _renewal_uncertain(
        self,
        target: EphemeralContainerTarget,
        *,
        phase: str,
        message: str,
    ) -> None:
        self._mark_attention(
            target.run_id,
            phase=phase,
            code="operation_outcome_uncertain",
            message=message,
        )
        self._wake.set()

    def _renewal_checkpoint(self, phase: str) -> None:
        """Test seam for crash-window recovery without a production side effect."""

    def _finish(self, accepted: AcceptedBrokerRequest) -> dict[str, Any]:
        request = accepted.request
        target = self._prepare_cleanup(
            accepted, reason=str(request.arguments["reason"])
        )
        if target.status == "cleaned":
            result = {**_public_target(target), "action": "finish", "changed": False}
            self._persistence.finish_operation(request.operation_id, result=result)
            return result
        try:
            result = self._cleanup(target, operation_id=request.operation_id)
            self._wake.set()
            return result
        except Exception as error:
            self._mark_attention(
                target.run_id,
                phase="cleanup_outcome_uncertain",
                code="operation_outcome_uncertain",
                message=(
                    "Ephemeral cleanup did not prove exact container absence; "
                    "the lease remains reserved pending reconciliation."
                ),
            )
            self._wake.set()
            raise BrokerBackendError(
                "operation_outcome_uncertain",
                "Ephemeral cleanup did not prove exact container absence; reconciliation is required.",
                operation_id=request.operation_id,
            ) from error

    def _recover_credential_renewal(
        self, target: EphemeralContainerTarget
    ) -> EphemeralContainerTarget:
        """Reconcile only the two expected durable/file transition states."""

        phase = target.credential_renewal_phase
        old_expiry = target.credential_renewal_old_expires_at_epoch
        new_expiry = target.credential_renewal_new_expires_at_epoch
        operation_id = target.credential_renewal_operation_id
        if (
            phase not in {"prepared", "committing"}
            or old_expiry is None
            or new_expiry is None
            or operation_id is None
        ):
            raise BrokerError(
                "operation_state_conflict",
                "Ephemeral credential renewal journal is invalid.",
            )
        try:
            observed = self._inspect_secret_expiry_renewal(
                target,
                new_expires_at_epoch=new_expiry,
            )
        except BrokerError:
            return self._fail_renewal_material_recovery(
                target,
                operation_id=operation_id,
                code="secret_delivery_unavailable",
                message=(
                    "The broker cannot prove volatile credential material while "
                    "recovering an interrupted renewal."
                ),
            )

        if phase == "prepared":
            if observed == "prepared":
                try:
                    self._rollback_secret_expiry_renewal(
                        target,
                        new_expires_at_epoch=new_expiry,
                    )
                except BrokerError:
                    return self._fail_renewal_material_recovery(
                        target,
                        operation_id=operation_id,
                        code="secret_delivery_unavailable",
                        message=(
                            "The broker cannot roll back volatile credential "
                            "material for an interrupted renewal."
                        ),
                    )
            elif observed not in {"old", "no_secret"}:
                return self._fail_renewal_material_recovery(
                    target,
                    operation_id=operation_id,
                    code="secret_delivery_unavailable",
                    message=(
                        "The volatile credential state does not match the "
                        "prepared renewal journal."
                    ),
                )
            return self._cancel_prepared_renewal(
                target,
                operation_id=operation_id,
                now_epoch=int(self._clock()),
            )

        if observed == "prepared":
            try:
                self._commit_secret_expiry_renewal(
                    target,
                    new_expires_at_epoch=new_expiry,
                    now_epoch=int(self._clock()),
                )
            except BrokerError:
                return self._fail_renewal_material_recovery(
                    target,
                    operation_id=operation_id,
                    code="secret_delivery_unavailable",
                    message=(
                        "The broker cannot complete volatile credential "
                        "material for a committed renewal."
                    ),
                )
        elif observed not in {"new", "no_secret"}:
            return self._fail_renewal_material_recovery(
                target,
                operation_id=operation_id,
                code="secret_delivery_unavailable",
                message=(
                    "The volatile credential state does not match the committed "
                    "renewal journal."
                ),
            )
        self._finalize_renewal(
            target,
            operation_id=operation_id,
            now_epoch=int(self._clock()),
        )
        return self._target(target.run_id)

    def _fail_renewal_material_recovery(
        self,
        target: EphemeralContainerTarget,
        *,
        operation_id: str,
        code: str,
        message: str,
    ) -> EphemeralContainerTarget:
        cleanup_target = self._persist_cleanup_intent(
            target.run_id,
            reason=message,
            code=code,
            message=message,
        )
        self._cleanup(
            cleanup_target,
            operation_id=None,
            reason=message,
            code=code,
            message=message,
        )
        self._finish_reserved_error(
            operation_id,
            code=code,
            message=message,
        )
        return self._target(target.run_id)

    def _cancel_renewal_for_cleanup(
        self, target: EphemeralContainerTarget
    ) -> EphemeralContainerTarget:
        """Let a durable cleanup intent dominate an interrupted renewal.

        Cleanup cannot safely wait for a prepared/committing credential
        renewal to become a normal running result: it may be the only path
        after a reboot has removed the volatile password.  Clear and
        terminalize the renewal journal before any Docker call, but retain the
        existing cleanup intent even when that Docker observation subsequently
        fails.
        """

        if not target.cleanup_requested:
            return target
        now_epoch = int(self._clock())
        now = utc_timestamp(now_epoch)
        with self._persistence._store() as store:
            with store.immediate_transaction() as connection:
                current = _target(connection, target.run_id)
                if current.status in {"cleaned", "failed"}:
                    return current
                if not current.cleanup_requested:
                    return current
                renewal_active = current.credential_renewal_phase != "none"
                if not renewal_active and current.status == "cleanup_pending":
                    return current
                renewal_operation_id = current.credential_renewal_operation_id
                interrupted_message = (
                    "Cleanup was requested before the credential renewal could "
                    "be reconciled."
                )
                renewal_error_code = (
                    current.error_code
                    if current.error_code is not None
                    else "ephemeral_renewal_interrupted"
                )
                renewal_error_message = (
                    current.error_message
                    if current.error_message is not None
                    else interrupted_message
                )
                phase = (
                    "cleanup_renewal_cancelled"
                    if renewal_active
                    else "cleanup_recovery_fenced"
                )
                connection.execute(
                    """
                    UPDATE ephemeral_container_runs
                    SET cleanup_requested = 1,
                        cleanup_reason = COALESCE(cleanup_reason, ?),
                        status = 'cleanup_pending', phase = ?,
                        credential_renewal_phase = 'none',
                        credential_renewal_old_expires_at_epoch = NULL,
                        credential_renewal_new_expires_at_epoch = NULL,
                        credential_renewal_operation_id = NULL,
                        error_code = CASE
                            WHEN ? AND error_code IS NULL
                            THEN 'ephemeral_renewal_interrupted'
                            ELSE error_code
                        END,
                        error_message = CASE
                            WHEN ? AND error_message IS NULL THEN ?
                            ELSE error_message
                        END,
                        next_reconcile_at_epoch = ?,
                        generation = generation + 1, updated_at = ?
                    WHERE run_id = ? AND cleanup_requested = 1
                      AND status NOT IN ('cleaned', 'failed')
                    """,
                    (
                        "Ephemeral cleanup was requested before recovery.",
                        phase,
                        renewal_active,
                        renewal_active,
                        interrupted_message,
                        now_epoch,
                        now,
                        current.run_id,
                    ),
                )
                if renewal_active:
                    _phase(
                        connection,
                        run_id=current.run_id,
                        phase=phase,
                        status="failed",
                        error={
                            "code": renewal_error_code,
                            "message": renewal_error_message,
                        },
                        recorded_at=now,
                    )
                if renewal_operation_id is not None:
                    operation = connection.execute(
                        """
                        SELECT operation.status
                        FROM operations operation
                        JOIN broker_operation_requests request USING(operation_id)
                        WHERE operation.operation_id = ? AND request.repo_id = ?
                          AND request.resource_id = ? AND request.operation = ?
                        """,
                        (
                            renewal_operation_id,
                            current.repo_id,
                            current.run_id,
                            BrokerOperation.EPHEMERAL_RENEW.value,
                        ),
                    ).fetchone()
                    if operation is not None and str(operation["status"]) == "running":
                        _finish_operation(
                            connection,
                            renewal_operation_id,
                            error_code=renewal_error_code,
                            error_message=renewal_error_message,
                        )
                return _target(connection, current.run_id)

    def _recover_target(self, target: EphemeralContainerTarget) -> None:
        if target.status in {"cleaned", "failed"}:
            return
        if target.cleanup_requested:
            self._cleanup(target, operation_id=None)
            return
        if target.credential_renewal_phase != "none":
            target = self._recover_credential_renewal(target)
            if target.status in {"cleaned", "failed"}:
                return
        found = self._host.docker_find_ephemeral(_identity(target))
        if not bool(found.get("found")):
            if target.status == "running":
                target = self._record_unexpected_exit(
                    target.run_id,
                    code="ephemeral_container_disappeared",
                    message="The running ephemeral container disappeared before its TTL.",
                )
            if target.full_container_id is not None:
                # Authoritative all-label absence after an immutable ID was
                # persisted means the exact resource is gone.  Release only
                # this run's lease and terminalize any interrupted start.
                self._complete_cleanup(target.run_id, operation_id=None)
            elif target.cleanup_requested or target.status in {
                "cleanup_pending",
                "stopping",
                "removing",
            }:
                # A create command may still finish after its client timed
                # out.  A Finish request therefore cannot terminalize on one
                # point-in-time absence until the full command-timeout grace
                # window has also stayed absent.
                if self._record_create_absence(target.run_id):
                    self._complete_cleanup(target.run_id, operation_id=None)
            elif target.status in {"creating", "needs_attention"}:
                if self._record_create_absence(target.run_id):
                    self._fail_before_create(
                        target.run_id,
                        code="ephemeral_create_not_found",
                        message=(
                            "Repeated exact-label observations stayed absent "
                            "through the bounded late-create grace window."
                        ),
                    )
            else:
                self._fail_before_create(
                    target.run_id,
                    code="ephemeral_create_not_found",
                    message=(
                        "Broker restart found no Docker container carrying the "
                        "precommitted creation identity."
                    ),
                )
            return

        full_id = _full_id(found.get("full_container_id"))
        if target.full_container_id is not None and target.full_container_id != full_id:
            raise BrokerBackendError(
                "ephemeral_docker_identity_mismatch",
                "Persisted run identity resolves to a different immutable container ID.",
            )
        if target.full_container_id is None:
            target = self._record_container(target.run_id, full_id)
        else:
            target = self._target(target.run_id)

        if target.cleanup_requested or target.status in {
            "cleanup_pending",
            "stopping",
            "removing",
        }:
            self._cleanup(target, operation_id=None)
            return
        if int(self._clock()) >= target.expires_at_epoch:
            code = "ephemeral_start_deadline_expired"
            message = "The ephemeral TTL elapsed before recovery could keep or start it."
            self._cleanup(
                target,
                operation_id=None,
                reason=message,
                code=code,
                message=message,
            )
            return
        if not self._recovery_start_permitted(target):
            code = "ephemeral_start_no_longer_permitted"
            message = "Ephemeral start authority is no longer valid during recovery."
            self._cleanup(
                target,
                operation_id=None,
                reason=message,
                code=code,
                message=message,
            )
            return

        # docker_find_ephemeral intentionally proves identity only so cleanup
        # remains possible after safety-profile drift.  Before recovery may
        # keep or start a container, require both the stricter sealed profile
        # and existing volatile credential material.  A host reboot removes
        # the RuntimeDirectory by design; a policy-backed process must then be
        # removed, never advertised as healthy or given a replacement password.
        try:
            inspected = self._host.docker_inspect_ephemeral(
                self._container_target(target, require_material=True)
            )
        except BrokerBackendError as error:
            if error.code not in _RECOVERY_PROFILE_CLEANUP_FAILURE_CODES:
                raise
            message = (
                "The ephemeral container's sealed image and safety profile could "
                "not be proved; recovery removed it instead of keeping or restarting it."
            )
            target = self._persist_cleanup_intent(
                target.run_id,
                reason=message,
                code=error.code,
                message=message,
            )
            self._cleanup(target, operation_id=None)
            return
        except BrokerError as error:
            if error.code != "secret_delivery_unavailable":
                raise
            message = (
                "The broker no longer has the volatile PostgreSQL credential "
                "required to keep this ephemeral container after recovery."
            )
            target = self._persist_cleanup_intent(
                target.run_id,
                reason=message,
                code=error.code,
                message=message,
            )
            self._cleanup(target, operation_id=None)
            return

        if bool(inspected.get("running")):
            self._complete_running_recovery(target.run_id, host_result=inspected)
            return
        if target.status == "running":
            target = self._record_unexpected_exit(
                target.run_id,
                code="ephemeral_container_exited",
                message="The ephemeral container exited before its TTL.",
            )
            self._cleanup(target, operation_id=None)
            return
        self._transition(
            target.run_id,
            expected={"attributed", "starting", "needs_attention", "creating"},
            status="starting",
            phase="recovery_start_invoked",
            tolerate_same=True,
        )
        try:
            container_target = self._container_target(target, require_material=True)
        except BrokerError as error:
            if error.code != "secret_delivery_unavailable":
                raise
            message = (
                "The broker no longer has the volatile PostgreSQL credential "
                "required to restart this ephemeral container."
            )
            target = self._persist_cleanup_intent(
                target.run_id,
                reason=message,
                code=error.code,
                message=message,
            )
            self._cleanup(target, operation_id=None)
            return
        started = self._host.docker_start_ephemeral(container_target)
        self._complete_running_recovery(target.run_id, host_result=started)

    def _cleanup(
        self,
        target: EphemeralContainerTarget,
        *,
        operation_id: str | None,
        reason: str | None = None,
        code: str | None = None,
        message: str | None = None,
    ) -> dict[str, Any]:
        target = self._persist_cleanup_intent(
            target.run_id,
            reason=(
                reason
                or target.cleanup_reason
                or "Ephemeral cleanup is required before this run can finish."
            ),
            code=code,
            message=message,
        )
        target = self._cancel_renewal_for_cleanup(target)
        found = self._host.docker_find_ephemeral(_identity(target))
        if not bool(found.get("found")):
            if target.full_container_id is None:
                if not self._record_create_absence(target.run_id):
                    raise BrokerBackendError(
                        "ephemeral_docker_absence_unconfirmed",
                        "Exact labels are absent, but the bounded late-create grace window has not elapsed.",
                    )
            return self._complete_cleanup(target.run_id, operation_id=operation_id)
        full_id = _full_id(found.get("full_container_id"))
        if target.full_container_id is None:
            target = self._record_container(target.run_id, full_id)
        elif target.full_container_id != full_id:
            raise BrokerBackendError(
                "ephemeral_docker_identity_mismatch",
                "Cleanup refused a container whose immutable identity differs from the run journal.",
            )
        container_target = self._container_target(target, require_material=False)
        if bool(found.get("running")):
            self._transition(
                target.run_id,
                expected=_ACTIVE_RUN_STATES,
                status="stopping",
                phase="docker_stop_invoked",
                tolerate_same=True,
            )
            self._host.docker_stop_ephemeral(container_target)
        self._transition(
            target.run_id,
            expected=_ACTIVE_RUN_STATES,
            status="removing",
            phase="docker_remove_invoked",
            tolerate_same=True,
        )
        self._host.docker_remove_ephemeral(container_target)
        absent = self._host.docker_find_ephemeral(_identity(target))
        if bool(absent.get("found")):
            raise BrokerBackendError(
                "ephemeral_docker_remove_outcome_unknown",
                "Docker remove returned but exact all-label absence was not proved.",
            )
        return self._complete_cleanup(target.run_id, operation_id=operation_id)

    def _prepare_start(
        self,
        accepted: AcceptedBrokerRequest,
        *,
        expected_image_ref: str | None = None,
        expected_template_fingerprint: str | None = None,
    ) -> EphemeralContainerTarget:
        request = accepted.request
        if request.operation is not BrokerOperation.EPHEMERAL_START:
            raise ValueError("request is not ephemeral.start")
        if (expected_image_ref is None) != (expected_template_fingerprint is None):
            raise ValueError("sealed image and template fingerprint must be supplied together")
        execution_uid = accepted.attribution_uid
        now_epoch = int(self._clock())
        now = utc_timestamp(now_epoch)
        with self._persistence._store() as store:
            with store.immediate_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                existing = connection.execute(
                    "SELECT run_id FROM ephemeral_container_runs WHERE run_id = ?",
                    (request.operation_id,),
                ).fetchone()
                if existing is not None:
                    return _target(connection, request.operation_id)
                template = connection.execute(
                    """
                    SELECT * FROM ephemeral_container_templates
                    WHERE template_id = ? AND repo_id = ? AND enabled = 1
                      AND (? IS NULL OR image_ref = ?)
                      AND (? IS NULL OR definition_fingerprint = ?)
                    """,
                    (
                        request.resource_id,
                        request.project_id,
                        expected_image_ref,
                        expected_image_ref,
                        expected_template_fingerprint,
                        expected_template_fingerprint,
                    ),
                ).fetchone()
                if template is None:
                    raise BrokerError(
                        "ephemeral_image_definition_changed",
                        "The sealed template changed after its exact image cache check; no container was created.",
                        operation_id=request.operation_id,
                    )
                ttl = int(
                    request.arguments.get(
                        "ttl_seconds", template["default_ttl_seconds"]
                    )
                )
                if ttl > int(template["max_ttl_seconds"]):
                    raise BrokerError(
                        "ttl_policy_denied",
                        "Requested TTL exceeds the administrator-sealed template policy.",
                        operation_id=request.operation_id,
                    )
                self._enforce_start_quotas(
                    connection,
                    template=template,
                    owner_uid=execution_uid,
                    operation_id=request.operation_id,
                )
                creation_nonce = str(uuid.uuid4())
                slug = str(template["name"])[:48].rstrip("-.")
                container_name = (
                    f"devcoordinator-{slug}-{uuid.UUID(request.operation_id).hex}"
                )
                expires = now_epoch + ttl
                connection.execute(
                    """
                    INSERT INTO ephemeral_container_runs(
                        run_id, template_id, repo_id, owner_uid, account_id,
                        creation_nonce, container_name, image_ref,
                        secret_policy_kind, secret_binding_id,
                        memory_bytes, cpu_millis, container_tcp_port,
                        host_port_start, host_port_end, template_fingerprint,
                        status, phase, max_ttl_seconds, expires_at_epoch,
                        next_reconcile_at_epoch, recovery_failures, generation,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                              'reserved', 'write_ahead_committed', ?, ?, ?, 0, 0, ?, ?)
                    """,
                    (
                        request.operation_id,
                        request.resource_id,
                        request.project_id,
                        execution_uid,
                        request.account_id,
                        creation_nonce,
                        container_name,
                        template["image_ref"],
                        template["secret_policy_kind"],
                        template["secret_binding_id"],
                        template["memory_bytes"],
                        template["cpu_millis"],
                        template["container_tcp_port"],
                        template["host_port_start"],
                        template["host_port_end"],
                        template["definition_fingerprint"],
                        template["max_ttl_seconds"],
                        expires,
                        now_epoch,
                        now,
                        now,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO ephemeral_run_arguments(run_id, ordinal, argument)
                    SELECT ?, ordinal, argument
                    FROM ephemeral_template_arguments WHERE template_id = ?
                    ORDER BY ordinal
                    """,
                    (request.operation_id, request.resource_id),
                )
                connection.execute(
                    """
                    INSERT INTO ephemeral_run_environment(run_id, name, value)
                    SELECT ?, name, value
                    FROM ephemeral_template_environment WHERE template_id = ?
                    ORDER BY name
                    """,
                    (request.operation_id, request.resource_id),
                )
                _phase(
                    connection,
                    run_id=request.operation_id,
                    phase="write_ahead_committed",
                    status="succeeded",
                    evidence={
                        "creation_nonce_fingerprint": "sha256:"
                        + fingerprint(creation_nonce),
                        "expires_at_epoch": expires,
                    },
                    recorded_at=now,
                )
                return _target(connection, request.operation_id)

    def _enforce_start_quotas(
        self,
        connection: sqlite3.Connection,
        *,
        template: sqlite3.Row,
        owner_uid: int,
        operation_id: str,
    ) -> None:
        """Reject over-budget starts inside the write-ahead transaction.

        The caller owns ``BEGIN IMMEDIATE``.  Reading every counter and
        inserting the run while that writer reservation is held makes quota
        admission serializable across broker processes, not merely across the
        coordinator object's in-memory mutation lock.
        """

        states = _ACTIVE_RUN_STATES_ORDERED
        placeholders = ",".join("?" for _ in states)
        template_id = str(template["template_id"])
        repo_id = str(template["repo_id"])
        proposed_memory = int(
            template["memory_bytes"]
            if template["memory_bytes"] is not None
            else _DEFAULT_EPHEMERAL_MEMORY_BYTES
        )
        proposed_cpu = int(
            template["cpu_millis"]
            if template["cpu_millis"] is not None
            else _DEFAULT_EPHEMERAL_CPU_MILLIS
        )
        usage = connection.execute(
            f"""
            SELECT
                COALESCE(SUM(CASE WHEN template_id = ? THEN 1 ELSE 0 END), 0)
                    AS template_runs,
                COALESCE(SUM(
                    CASE WHEN template_id = ? AND owner_uid = ? THEN 1 ELSE 0 END
                ), 0) AS owner_template_runs,
                COUNT(*) AS repo_runs,
                COALESCE(SUM(COALESCE(memory_bytes, ?)), 0) AS repo_memory_bytes,
                COALESCE(SUM(COALESCE(cpu_millis, ?)), 0) AS repo_cpu_millis
            FROM ephemeral_container_runs
            WHERE repo_id = ? AND status IN ({placeholders})
            """,
            (
                template_id,
                template_id,
                owner_uid,
                _DEFAULT_EPHEMERAL_MEMORY_BYTES,
                _DEFAULT_EPHEMERAL_CPU_MILLIS,
                repo_id,
                *states,
            ),
        ).fetchone()
        if usage is None:
            raise RuntimeError("ephemeral quota query returned no aggregate row")

        checks = (
            (
                int(usage["template_runs"])
                >= int(template["max_concurrent_runs"]),
                "The administrator-sealed concurrent-run limit for this template has been reached.",
            ),
            (
                int(usage["owner_template_runs"])
                >= int(template["max_concurrent_runs_per_uid"]),
                "The administrator-sealed per-user concurrent-run limit for this template has been reached.",
            ),
            (
                int(usage["repo_runs"]) >= int(template["repo_max_active_runs"]),
                "The administrator-sealed repository concurrent-run limit has been reached.",
            ),
            (
                int(usage["repo_memory_bytes"]) + proposed_memory
                > int(template["repo_memory_budget_bytes"]),
                "The administrator-sealed repository memory budget would be exceeded.",
            ),
            (
                int(usage["repo_cpu_millis"]) + proposed_cpu
                > int(template["repo_cpu_budget_millis"]),
                "The administrator-sealed repository CPU budget would be exceeded.",
            ),
        )
        for exceeded, message in checks:
            if exceeded:
                raise BrokerError(
                    "ephemeral_quota_exceeded",
                    message,
                    operation_id=operation_id,
                )

        host_usage = connection.execute(
            f"""
            SELECT COUNT(*) AS active_runs
            FROM ephemeral_container_runs run
            JOIN repositories repository ON repository.repo_id = run.repo_id
            WHERE repository.host_id = (
                SELECT host_id FROM repositories WHERE repo_id = ?
            )
              AND run.status IN ({placeholders})
            """,
            (repo_id, *states),
        ).fetchone()
        if host_usage is None:
            raise RuntimeError("ephemeral host quota query returned no aggregate row")
        if int(host_usage["active_runs"]) >= _HOST_MAX_ACTIVE_EPHEMERAL_RUNS:
            raise BrokerError(
                "ephemeral_quota_exceeded",
                "The broker-wide active ephemeral-container limit has been reached on this host.",
                operation_id=operation_id,
            )

    def _port_candidates(
        self, accepted: AcceptedBrokerRequest, run_id: str
    ) -> tuple[int, ...]:
        request = accepted.request
        with self._persistence._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                target = _target(connection, run_id)
                if target.host_port is not None:
                    return (target.host_port,)
                if target.host_port_start is None or target.host_port_end is None:
                    return ()
                host = connection.execute(
                    "SELECT host_id FROM repositories WHERE repo_id = ?",
                    (target.repo_id,),
                ).fetchone()
                if host is None:
                    raise BrokerError(
                        "repository_unavailable", "Ephemeral repository is unavailable."
                    )
                occupied = {
                    int(row[0])
                    for row in connection.execute(
                        """
                        SELECT port FROM leases WHERE host_id = ? AND status = 'active'
                        UNION
                        SELECT port FROM port_assignments
                        WHERE host_id = ? AND status = 'active'
                        """,
                        (host["host_id"], host["host_id"]),
                    )
                }
                return tuple(
                    port
                    for port in range(target.host_port_start, target.host_port_end + 1)
                    if port not in occupied
                )

    def _bind_port(
        self,
        accepted: AcceptedBrokerRequest,
        run_id: str,
        selected_port: int,
    ) -> EphemeralContainerTarget:
        request = accepted.request
        now = utc_timestamp()
        with self._persistence._store() as store:
            with store.immediate_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                target = _target(connection, run_id)
                if target.host_port is not None:
                    if target.host_port != selected_port:
                        raise BrokerError(
                            "lease_state_conflict",
                            "Ephemeral run already owns a different host port.",
                            operation_id=request.operation_id,
                        )
                    return target
                if (
                    target.host_port_start is None
                    or target.host_port_end is None
                    or not target.host_port_start
                    <= selected_port
                    <= target.host_port_end
                ):
                    raise BrokerError(
                        "port_policy_denied",
                        "Selected host port is outside the sealed template policy.",
                        operation_id=request.operation_id,
                    )
                host = connection.execute(
                    "SELECT host_id FROM repositories WHERE repo_id = ?",
                    (target.repo_id,),
                ).fetchone()
                if host is None:
                    raise BrokerError(
                        "repository_unavailable", "Ephemeral repository is unavailable."
                    )
                occupied = connection.execute(
                    """
                    SELECT 1 FROM leases
                    WHERE host_id = ? AND port = ? AND status = 'active'
                    UNION ALL
                    SELECT 1 FROM port_assignments
                    WHERE host_id = ? AND port = ? AND status = 'active'
                    LIMIT 1
                    """,
                    (
                        host["host_id"],
                        selected_port,
                        host["host_id"],
                        selected_port,
                    ),
                ).fetchone()
                if occupied is not None:
                    raise BrokerError(
                        "port_unavailable",
                        "Ephemeral host port was claimed concurrently; retry with a new operation ID.",
                        operation_id=request.operation_id,
                    )
                lease_id = "ephemeral-lease-" + target.run_id
                try:
                    connection.execute(
                        """
                        INSERT INTO leases(
                            lease_id, host_id, repo_id, server_definition_id,
                            port, owner, agent, purpose, status, expires_at,
                            generation, created_at, updated_at
                        ) VALUES (?, ?, ?, NULL, ?, ?, ?, ?, 'active', ?, 0, ?, ?)
                        """,
                        (
                            lease_id,
                            host["host_id"],
                            target.repo_id,
                            selected_port,
                            f"uid:{target.owner_uid}",
                            target.account_id,
                            "ephemeral:" + target.run_id,
                            utc_timestamp(target.expires_at_epoch),
                            now,
                            now,
                        ),
                    )
                except sqlite3.IntegrityError as error:
                    raise BrokerError(
                        "port_unavailable",
                        "Ephemeral host port was claimed concurrently; retry with a new operation ID.",
                        operation_id=request.operation_id,
                    ) from error
                connection.execute(
                    """
                    UPDATE ephemeral_container_runs
                    SET lease_id = ?, host_port = ?, phase = 'port_reserved',
                        generation = generation + 1, updated_at = ?
                    WHERE run_id = ? AND status = 'reserved'
                    """,
                    (lease_id, selected_port, now, run_id),
                )
                _phase(
                    connection,
                    run_id=run_id,
                    phase="port_reserved",
                    status="succeeded",
                    evidence={"host_port": selected_port},
                    recorded_at=now,
                )
                return _target(connection, run_id)

    def _record_container(
        self,
        run_id: str,
        full_container_id: str,
        *,
        accepted: AcceptedBrokerRequest | None = None,
    ) -> EphemeralContainerTarget:
        full_id = _full_id(full_container_id)
        now = utc_timestamp()
        with self._persistence._store() as store:
            with store.immediate_transaction() as connection:
                if accepted is not None:
                    _validate_connection_request(
                        connection,
                        peer=accepted.peer,
                        request=accepted.request,
                    )
                target = _target(connection, run_id)
                if target.full_container_id is not None and target.full_container_id != full_id:
                    raise BrokerError(
                        "ephemeral_docker_identity_mismatch",
                        "Run already records a different immutable container ID.",
                    )
                connection.execute(
                    """
                    UPDATE ephemeral_container_runs
                    SET full_container_id = ?,
                        status = CASE
                            WHEN cleanup_requested = 1 THEN 'cleanup_pending'
                            ELSE 'attributed'
                        END,
                        phase = 'immutable_id_persisted',
                        create_absence_since_epoch = NULL,
                        create_absence_observations = 0,
                        generation = generation + 1, updated_at = ?
                    WHERE run_id = ? AND status IN (
                        'reserved', 'creating', 'attributed', 'starting',
                        'running', 'needs_attention', 'cleanup_pending'
                    )
                    """,
                    (full_id, now, run_id),
                )
                _phase(
                    connection,
                    run_id=run_id,
                    phase="immutable_id_persisted",
                    status="succeeded",
                    evidence={"full_container_id": full_id},
                    recorded_at=now,
                )
                return _target(connection, run_id)

    def _persist_cleanup_intent(
        self,
        run_id: str,
        *,
        reason: str,
        code: str | None = None,
        message: str | None = None,
    ) -> EphemeralContainerTarget:
        """Write cleanup intent before any fallible Docker cleanup boundary."""

        now_epoch = int(self._clock())
        now = utc_timestamp(now_epoch)
        with self._persistence._store() as store:
            with store.immediate_transaction() as connection:
                target = _target(connection, run_id)
                if target.status in {"cleaned", "failed"}:
                    return target
                first_request = not target.cleanup_requested
                phase = (
                    "cleanup_intent_persisted"
                    if first_request
                    else "cleanup_retry_pending"
                )
                connection.execute(
                    """
                    UPDATE ephemeral_container_runs
                    SET cleanup_requested = 1,
                        cleanup_reason = COALESCE(cleanup_reason, ?),
                        status = 'cleanup_pending', phase = ?,
                        error_code = CASE
                            WHEN ? IS NULL THEN error_code ELSE ?
                        END,
                        error_message = CASE
                            WHEN ? IS NULL THEN error_message ELSE ?
                        END,
                        next_reconcile_at_epoch = ?,
                        generation = generation + 1, updated_at = ?
                    WHERE run_id = ? AND status NOT IN ('cleaned', 'failed')
                    """,
                    (
                        reason,
                        phase,
                        code,
                        code,
                        message,
                        message,
                        now_epoch,
                        now,
                        run_id,
                    ),
                )
                if first_request:
                    _phase(
                        connection,
                        run_id=run_id,
                        phase=phase,
                        status="succeeded",
                        evidence={"reason": reason},
                        error=(
                            None
                            if code is None
                            else {"code": code, "message": message or reason}
                        ),
                        recorded_at=now,
                    )
                    if code is not None:
                        _event(
                            connection,
                            run_id=run_id,
                            repo_id=target.repo_id,
                            operation_id=run_id,
                            event_kind="ephemeral.failed",
                            code=code,
                            message=message or reason,
                            diagnostic={
                                "full_container_id": target.full_container_id
                            },
                            occurred_at=now,
                        )
                return _target(connection, run_id)

    def _record_create_absence(self, run_id: str) -> bool:
        """Require repeated absence for a full Docker-command timeout window."""

        now_epoch = int(self._clock())
        now = utc_timestamp(now_epoch)
        with self._persistence._store() as store:
            with store.immediate_transaction() as connection:
                row = connection.execute(
                    """
                    SELECT create_absence_since_epoch, create_absence_observations
                    FROM ephemeral_container_runs
                    WHERE run_id = ? AND full_container_id IS NULL
                      AND status NOT IN ('cleaned', 'failed')
                      AND (
                          cleanup_requested = 1
                          OR status IN ('creating', 'needs_attention')
                      )
                    """,
                    (run_id,),
                ).fetchone()
                if row is None:
                    return False
                since = (
                    now_epoch
                    if row["create_absence_since_epoch"] is None
                    else int(row["create_absence_since_epoch"])
                )
                observations = int(row["create_absence_observations"]) + 1
                stable = observations >= 2 and now_epoch - since >= 60
                connection.execute(
                    """
                    UPDATE ephemeral_container_runs
                    SET create_absence_since_epoch = ?,
                        create_absence_observations = ?,
                        next_reconcile_at_epoch = ?,
                        phase = 'create_absence_observed',
                        generation = generation + 1, updated_at = ?
                    WHERE run_id = ?
                    """,
                    (since, observations, now_epoch + 10, now, run_id),
                )
                if observations == 1 or stable:
                    _phase(
                        connection,
                        run_id=run_id,
                        phase="create_absence_observed",
                        status="succeeded" if stable else "running",
                        evidence={
                            "observations": observations,
                            "grace_elapsed_seconds": now_epoch - since,
                        },
                        recorded_at=now,
                    )
                return stable

    def _record_unexpected_exit(
        self, run_id: str, *, code: str, message: str
    ) -> EphemeralContainerTarget:
        now = utc_timestamp()
        with self._persistence._store() as store:
            with store.immediate_transaction() as connection:
                target = _target(connection, run_id)
                if target.status != "running":
                    return target
                connection.execute(
                    """
                    UPDATE ephemeral_container_runs
                    SET status = 'cleanup_pending', phase = 'unexpected_exit',
                        cleanup_requested = 1, cleanup_reason = ?,
                        error_code = ?, error_message = ?,
                        generation = generation + 1, updated_at = ?
                    WHERE run_id = ? AND status = 'running'
                    """,
                    (message, code, message, now, run_id),
                )
                _phase(
                    connection,
                    run_id=run_id,
                    phase="unexpected_exit",
                    status="failed",
                    error={"code": code, "message": message},
                    recorded_at=now,
                )
                _event(
                    connection,
                    run_id=run_id,
                    repo_id=target.repo_id,
                    operation_id=run_id,
                    event_kind="ephemeral.failed",
                    code=code,
                    message=message,
                    diagnostic={"full_container_id": None},
                    occurred_at=now,
                )
                _event(
                    connection,
                    run_id=run_id,
                    repo_id=target.repo_id,
                    operation_id=None,
                    event_kind="ephemeral.crashed",
                    code=code,
                    message=message,
                    diagnostic={"full_container_id": target.full_container_id},
                    occurred_at=now,
                )
                return _target(connection, run_id)

    def _complete_running(
        self,
        accepted: AcceptedBrokerRequest,
        run_id: str,
        *,
        host_result: Mapping[str, Any],
    ) -> dict[str, Any]:
        request = accepted.request
        with self._persistence._store() as store:
            with store.immediate_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                return self._complete_running_connection(
                    connection,
                    run_id,
                    host_result=host_result,
                    operation_id=request.operation_id,
                )

    def _complete_running_recovery(
        self, run_id: str, *, host_result: Mapping[str, Any]
    ) -> dict[str, Any]:
        with self._persistence._store() as store:
            with store.immediate_transaction() as connection:
                return self._complete_running_connection(
                    connection,
                    run_id,
                    host_result=host_result,
                    operation_id=run_id,
                )

    def _complete_running_connection(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        *,
        host_result: Mapping[str, Any],
        operation_id: str,
    ) -> dict[str, Any]:
        target = _target(connection, run_id)
        full_id = _full_id(host_result.get("full_container_id"))
        if target.cleanup_requested:
            raise BrokerError(
                "ephemeral_cleanup_requested",
                "Recovery refused to mark a run running after cleanup was requested.",
                operation_id=operation_id,
            )
        if target.full_container_id != full_id or host_result.get("running") is not True:
            raise BrokerError(
                "ephemeral_docker_identity_mismatch",
                "Docker start evidence does not match the persisted run identity.",
                operation_id=operation_id,
            )
        start_operation = connection.execute(
            "SELECT status FROM operations WHERE operation_id = ?", (run_id,)
        ).fetchone()
        already_published = bool(
            start_operation is not None
            and str(start_operation["status"]) == "succeeded"
        )
        if target.status == "running" or already_published:
            now_epoch = int(self._clock())
            connection.execute(
                """
                UPDATE ephemeral_container_runs
                SET status = 'running', phase = 'running',
                    next_reconcile_at_epoch = ?, recovery_failures = 0,
                    error_code = NULL, error_message = NULL,
                    generation = generation + 1, updated_at = ?
                WHERE run_id = ? AND status != 'cleaned'
                """,
                (now_epoch + 60, utc_timestamp(now_epoch), run_id),
            )
            if target.status != "running":
                _phase(
                    connection,
                    run_id=run_id,
                    phase="running_reconciled",
                    status="succeeded",
                    evidence={"full_container_id": full_id},
                    recorded_at=utc_timestamp(now_epoch),
                )
            return {
                **_public_target(_target(connection, run_id)),
                "action": "start",
                "changed": False,
            }
        now = utc_timestamp()
        next_reconcile = int(self._clock()) + 60
        connection.execute(
            """
            UPDATE ephemeral_container_runs
            SET status = 'running', phase = 'running', error_code = NULL,
                error_message = NULL, next_reconcile_at_epoch = ?,
                recovery_failures = 0, generation = generation + 1,
                updated_at = ?
            WHERE run_id = ? AND status != 'cleaned'
            """,
            (next_reconcile, now, run_id),
        )
        _phase(
            connection,
            run_id=run_id,
            phase="running",
            status="succeeded",
            evidence={"full_container_id": full_id},
            recorded_at=now,
        )
        result = {
            **_public_target(_target(connection, run_id)),
            "action": "start",
            "changed": True,
        }
        _event(
            connection,
            run_id=run_id,
            repo_id=target.repo_id,
            operation_id=operation_id,
            event_kind="ephemeral.started",
            code="ephemeral_started",
            message=f"Ephemeral container {target.container_name} started",
            diagnostic={
                "full_container_id": full_id,
                "expires_at_epoch": target.expires_at_epoch,
            },
            occurred_at=now,
        )
        if start_operation is not None and str(start_operation["status"]) == "running":
            _finish_operation(connection, run_id, result=result)
        return result

    def _prepare_cleanup(
        self, accepted: AcceptedBrokerRequest, *, reason: str
    ) -> EphemeralContainerTarget:
        request = accepted.request
        now = utc_timestamp()
        with self._persistence._store() as store:
            with store.immediate_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                target = _target(connection, request.resource_id)
                if target.status == "cleaned":
                    return target
                connection.execute(
                    """
                    UPDATE ephemeral_container_runs
                    SET status = 'cleanup_pending', phase = 'cleanup_requested',
                        cleanup_requested = 1, cleanup_reason = ?,
                        generation = generation + 1,
                        updated_at = ?
                    WHERE run_id = ? AND status != 'cleaned'
                    """,
                    (reason, now, target.run_id),
                )
                _phase(
                    connection,
                    run_id=target.run_id,
                    phase="cleanup_requested",
                    status="succeeded",
                    evidence={"reason": reason},
                    recorded_at=now,
                )
                return _target(connection, target.run_id)

    def _complete_cleanup(
        self, run_id: str, *, operation_id: str | None
    ) -> dict[str, Any]:
        # Docker absence is proved by the caller before terminal state is
        # recorded.  Remove the volatile material first: a cleanup failure
        # keeps the durable run pending for safe retry rather than claiming a
        # completed lifecycle while a password file remains on the host.
        self._release_run_secret(run_id)
        now = utc_timestamp()
        with self._persistence._store() as store:
            with store.immediate_transaction() as connection:
                target = _target(connection, run_id)
                pending_finish_ids = tuple(
                    str(row["operation_id"])
                    for row in connection.execute(
                        """
                        SELECT request.operation_id
                        FROM broker_operation_requests request
                        JOIN operations operation USING(operation_id)
                        WHERE request.repo_id = ? AND request.resource_id = ?
                          AND request.operation = 'ephemeral.finish'
                          AND operation.status = 'running'
                        ORDER BY operation.created_at, request.operation_id
                        """,
                        (target.repo_id, run_id),
                    )
                )
                effective_operation_id = operation_id or (
                    pending_finish_ids[0] if pending_finish_ids else None
                )
                if target.lease_id is not None:
                    connection.execute(
                        """
                        UPDATE leases SET status = 'released', deactivated_at = ?,
                            updated_at = ?, generation = generation + 1
                        WHERE lease_id = ? AND status = 'active'
                        """,
                        (now, now, target.lease_id),
                    )
                start_operation = connection.execute(
                    """
                    SELECT operation.status
                    FROM operations operation
                    JOIN broker_operation_requests request USING(operation_id)
                    WHERE operation.operation_id = ?
                      AND request.operation = 'ephemeral.start'
                    """,
                    (run_id,),
                ).fetchone()
                if (
                    start_operation is not None
                    and str(start_operation["status"]) == "running"
                ):
                    start_error_code = (
                        target.error_code
                        if target.error_code in _START_CLEANUP_RESULT_CODES
                        else "ephemeral_ended_before_running"
                    )
                    start_error_message = (
                        target.error_message
                        if start_error_code == target.error_code
                        and target.error_message is not None
                        else (
                            "The ephemeral run ended before its original start "
                            "operation could be durably completed."
                        )
                    )
                    _finish_operation(
                        connection,
                        run_id,
                        error_code=start_error_code,
                        error_message=start_error_message,
                    )
                renewal_operation_id = target.credential_renewal_operation_id
                if (
                    target.credential_renewal_phase != "none"
                    and renewal_operation_id is not None
                ):
                    renewal_operation = connection.execute(
                        """
                        SELECT operation.status
                        FROM operations operation
                        JOIN broker_operation_requests request USING(operation_id)
                        WHERE operation.operation_id = ? AND request.repo_id = ?
                          AND request.resource_id = ? AND request.operation = ?
                        """,
                        (
                            renewal_operation_id,
                            target.repo_id,
                            target.run_id,
                            BrokerOperation.EPHEMERAL_RENEW.value,
                        ),
                    ).fetchone()
                    if (
                        renewal_operation is not None
                        and str(renewal_operation["status"]) == "running"
                    ):
                        _finish_operation(
                            connection,
                            renewal_operation_id,
                            error_code=(
                                target.error_code
                                or "ephemeral_renewal_interrupted"
                            ),
                            error_message=(
                                target.error_message
                                or (
                                    "The ephemeral run was cleaned before its "
                                    "credential renewal could be reconciled."
                                )
                            ),
                        )
                connection.execute(
                    """
                    UPDATE ephemeral_container_runs
                    SET status = 'cleaned', phase = 'absence_proved',
                        credential_renewal_phase = 'none',
                        credential_renewal_old_expires_at_epoch = NULL,
                        credential_renewal_new_expires_at_epoch = NULL,
                        credential_renewal_operation_id = NULL,
                        error_code = NULL, error_message = NULL,
                        generation = generation + 1, updated_at = ?,
                        finished_at = COALESCE(finished_at, ?)
                    WHERE run_id = ?
                    """,
                    (now, now, run_id),
                )
                _phase(
                    connection,
                    run_id=run_id,
                    phase="absence_proved",
                    status="succeeded",
                    evidence={"lease_released": target.lease_id is not None},
                    recorded_at=now,
                )
                result = {
                    **_public_target(_target(connection, run_id)),
                    "action": "finish",
                    "changed": target.status != "cleaned",
                }
                _event(
                    connection,
                    run_id=run_id,
                    repo_id=target.repo_id,
                    operation_id=effective_operation_id,
                    event_kind="ephemeral.cleaned",
                    code="ephemeral_cleaned",
                    message=f"Ephemeral container {target.container_name} was removed",
                    diagnostic={"full_container_id": target.full_container_id},
                    occurred_at=now,
                )
                for pending_operation_id in pending_finish_ids:
                    _finish_operation(connection, pending_operation_id, result=result)
                return result

    def _terminalize_reserved_start_before_host(
        self, request: Any, *, code: str, message: str
    ) -> None:
        """Fail a write-ahead Start only while Docker provably was not invoked."""

        if request.operation is not BrokerOperation.EPHEMERAL_START:
            return
        target = self._target_or_none(request.operation_id)
        if (
            target is None
            or target.status != "reserved"
            or target.full_container_id is not None
        ):
            return
        try:
            self._fail_before_create(
                request.operation_id,
                code=code,
                message=message,
                expected_statuses={"reserved"},
            )
        except Exception:
            # Preserve the caller-visible primary failure.  The operation
            # terminalizer below still records it, and service logging retains
            # this separate state-cleanup failure for operator diagnosis.
            _LOGGER.exception(
                "failed to terminalize pre-host ephemeral run %s",
                request.operation_id,
            )

    def _fail_before_create(
        self,
        run_id: str,
        *,
        code: str,
        message: str,
        expected_statuses: set[str] | frozenset[str] | None = None,
    ) -> bool:
        now = utc_timestamp()
        with self._persistence._store() as store:
            with store.immediate_transaction() as connection:
                target = _target(connection, run_id)
                if target.status in {"failed", "cleaned"}:
                    return False
                if (
                    expected_statuses is not None
                    and target.status not in expected_statuses
                ):
                    return False
                if target.full_container_id is not None:
                    raise BrokerError(
                        "operation_outcome_uncertain",
                        "Cannot terminally fail a run that already records a container ID.",
                    )
                if target.lease_id is not None:
                    connection.execute(
                        """
                        UPDATE leases SET status = 'released', deactivated_at = ?,
                            updated_at = ?, generation = generation + 1
                        WHERE lease_id = ? AND status = 'active'
                        """,
                        (now, now, target.lease_id),
                    )
                # No container identity was ever persisted, so releasing the
                # run-bound password cannot invalidate a live Docker mount.
                # If it fails, leave the durable row non-terminal for retry.
                self._release_run_secret(run_id)
                connection.execute(
                    """
                    UPDATE ephemeral_container_runs
                    SET status = 'failed', phase = 'create_not_observed',
                        error_code = ?, error_message = ?, updated_at = ?,
                        finished_at = COALESCE(finished_at, ?),
                        generation = generation + 1
                    WHERE run_id = ?
                    """,
                    (code, message, now, now, run_id),
                )
                _phase(
                    connection,
                    run_id=run_id,
                    phase="create_not_observed",
                    status="failed",
                    error={"code": code, "message": message},
                    recorded_at=now,
                )
                _event(
                    connection,
                    run_id=run_id,
                    repo_id=target.repo_id,
                    operation_id=run_id,
                    event_kind="ephemeral.failed",
                    code=code,
                    message=message,
                    diagnostic={"full_container_id": None},
                    occurred_at=now,
                )
                operation = connection.execute(
                    "SELECT status FROM operations WHERE operation_id = ?", (run_id,)
                ).fetchone()
                if operation is not None and str(operation["status"]) == "running":
                    _finish_operation(
                        connection,
                        run_id,
                        error_code=code,
                        error_message=message,
                    )
                return True

    def _mark_attention(
        self, run_id: str, *, phase: str, code: str, message: str
    ) -> None:
        now = utc_timestamp()
        try:
            with self._persistence._store() as store:
                with store.immediate_transaction() as connection:
                    row = connection.execute(
                        """
                        SELECT status, recovery_failures, cleanup_requested,
                               error_code, error_message
                        FROM ephemeral_container_runs WHERE run_id = ?
                        """,
                        (run_id,),
                    ).fetchone()
                    if row is None or str(row["status"]) in {"cleaned", "failed"}:
                        return
                    connection.execute(
                        """
                        UPDATE ephemeral_container_runs
                        SET status = 'needs_attention', phase = ?,
                            error_code = CASE
                                WHEN cleanup_requested = 1
                                 AND error_code IS NOT NULL
                                THEN error_code ELSE ?
                            END,
                            error_message = CASE
                                WHEN cleanup_requested = 1
                                 AND error_message IS NOT NULL
                                THEN error_message ELSE ?
                            END,
                            recovery_failures = recovery_failures + 1,
                            next_reconcile_at_epoch = ?, updated_at = ?,
                            generation = generation + 1
                        WHERE run_id = ?
                        """,
                        (
                            phase,
                            code,
                            message,
                            int(self._clock())
                            + min(3600, 15 * (2 ** min(8, int(row["recovery_failures"])))),
                            now,
                            run_id,
                        ),
                    )
                    _phase(
                        connection,
                        run_id=run_id,
                        phase=phase,
                        status="failed",
                        error={"code": code, "message": message},
                        recorded_at=now,
                    )
        except Exception:
            _LOGGER.exception("failed to persist ephemeral attention state for %s", run_id)

    def _finish_reserved_error(self, operation_id: str, *, code: str, message: str) -> None:
        """Terminalize one deterministic post-reservation rejection exactly once."""

        with self._persistence._store() as store:
            with store.immediate_transaction() as connection:
                row = connection.execute(
                    "SELECT status FROM operations WHERE operation_id = ?",
                    (operation_id,),
                ).fetchone()
                if row is not None and str(row["status"]) == "running":
                    _finish_operation(
                        connection,
                        operation_id,
                        error_code=code,
                        error_message=message,
                    )

    def _status(self, accepted: AcceptedBrokerRequest) -> dict[str, Any]:
        request = accepted.request
        with self._persistence._store() as store:
            with store.read_transaction() as connection:
                _validate_connection_request(
                    connection, peer=accepted.peer, request=request
                )
                target = _target(connection, request.resource_id)
                return {**_public_target(target), "action": "status"}

    def _transition(
        self,
        run_id: str,
        *,
        expected: frozenset[str] | set[str],
        status: str,
        phase: str,
        tolerate_same: bool = False,
    ) -> None:
        now = utc_timestamp()
        with self._persistence._store() as store:
            with store.immediate_transaction() as connection:
                target = _target(connection, run_id)
                if tolerate_same and target.status == status:
                    return
                if target.status not in expected:
                    raise BrokerError(
                        "operation_state_conflict",
                        "Ephemeral run changed before its next exact phase.",
                    )
                connection.execute(
                    """
                    UPDATE ephemeral_container_runs
                    SET status = ?, phase = ?, updated_at = ?,
                        generation = generation + 1
                    WHERE run_id = ?
                    """,
                    (status, phase, now, run_id),
                )
                _phase(
                    connection,
                    run_id=run_id,
                    phase=phase,
                    status="running",
                    recorded_at=now,
                )

    def _target(self, run_id: str) -> EphemeralContainerTarget:
        with self._persistence._store() as store:
            with store.read_transaction() as connection:
                return _target(connection, run_id)

    def _target_or_none(self, run_id: str) -> EphemeralContainerTarget | None:
        try:
            return self._target(run_id)
        except BrokerError:
            return None

    def _recovery_targets(
        self, *, due_before: int | None = None, limit: int | None = None
    ) -> tuple[EphemeralContainerTarget, ...]:
        if limit is not None and limit <= 0:
            raise ValueError("ephemeral recovery target limit must be positive")
        with self._persistence._store() as store:
            with store.read_transaction() as connection:
                if due_before is None:
                    if limit is None:
                        rows = connection.execute(
                            """
                            SELECT run_id FROM ephemeral_container_runs
                            WHERE status NOT IN ('cleaned', 'failed')
                            ORDER BY created_at, run_id
                            """
                        ).fetchall()
                    else:
                        rows = connection.execute(
                            """
                            SELECT run_id FROM ephemeral_container_runs
                            WHERE status NOT IN ('cleaned', 'failed')
                            ORDER BY created_at, run_id
                            LIMIT ?
                            """,
                            (limit,),
                        ).fetchall()
                else:
                    rows = connection.execute(
                        """
                        SELECT run_id FROM ephemeral_container_runs
                        WHERE status NOT IN ('cleaned', 'failed')
                          AND (expires_at_epoch <= ?
                               OR next_reconcile_at_epoch <= ?)
                        ORDER BY
                          CASE WHEN expires_at_epoch <= ? THEN 0 ELSE 1 END,
                          next_reconcile_at_epoch, run_id
                        LIMIT 32
                        """,
                        (due_before, due_before, due_before),
                    ).fetchall()
                return tuple(_target(connection, str(row["run_id"])) for row in rows)

    def _policy_recovery_targets(self) -> tuple[EphemeralContainerTarget, ...]:
        """Return every nonterminal credential-backed run without a host bound.

        Startup material fencing is a local filesystem proof, not a Docker
        operation, so it must cover the whole active set before the bounded
        host-recovery batch is allowed to admit clients.
        """

        with self._persistence._store() as store:
            with store.read_transaction() as connection:
                rows = connection.execute(
                    """
                    SELECT run_id FROM ephemeral_container_runs
                    WHERE status NOT IN ('cleaned', 'failed')
                      AND secret_policy_kind IS NOT NULL
                    ORDER BY created_at, run_id
                    """
                ).fetchall()
                return tuple(_target(connection, str(row["run_id"])) for row in rows)

    def _active_recovery_count(self) -> int:
        with self._persistence._store() as store:
            with store.read_transaction() as connection:
                return int(
                    connection.execute(
                        """
                        SELECT COUNT(*) FROM ephemeral_container_runs
                        WHERE status NOT IN ('cleaned', 'failed')
                        """
                    ).fetchone()[0]
                )

    def _recovery_start_permitted(self, target: EphemeralContainerTarget) -> bool:
        """Revalidate exact resource availability before starting the container.

        Local principal, configuration, ACL, and expiry rows are not an
        authorization boundary on a single-developer server.  The durable run
        already carries its exact repository/template binding and execution
        identity.  Revalidation therefore fences only actual resource state;
        later image, policy-material, and immutable-container checks still
        protect the host boundary.
        """

        with self._persistence._store() as store:
            with store.read_transaction() as connection:
                row = connection.execute(
                    """
                    SELECT template.enabled AS template_enabled,
                           repository.state AS repository_state,
                           installation.status AS installation_status,
                           installation.startup_fenced
                    FROM ephemeral_container_templates template
                    JOIN repositories repository USING(repo_id)
                    JOIN repository_installations installation USING(repo_id)
                    WHERE template.template_id = ? AND template.repo_id = ?
                    """,
                    (
                        target.template_id,
                        target.repo_id,
                    ),
                ).fetchone()
                return bool(
                    row is not None
                    and row["template_enabled"]
                    and row["repository_state"] == "active"
                    and row["installation_status"] == "installed"
                    and not row["startup_fenced"]
                )

    @staticmethod
    def _create_target(
        target: EphemeralContainerTarget,
        *,
        secret_mount: EphemeralSecretMount | None = None,
    ) -> EphemeralDockerCreateTarget:
        environment = target.environment
        if secret_mount is not None:
            if any(name == "POSTGRES_PASSWORD_FILE" for name, _ in environment):
                raise BrokerError(
                    "secret_delivery_unavailable",
                    "The sealed template conflicts with the broker-owned PostgreSQL password-file setting.",
                )
            environment = (*environment, *secret_mount.environment)
        return EphemeralDockerCreateTarget(
            identity=_identity(target),
            owner_uid=target.owner_uid,
            container_name=target.container_name,
            image_ref=target.image_ref,
            command=target.command,
            environment=environment,
            secret_mount=secret_mount,
            memory_bytes=target.memory_bytes or 512 * 1024 * 1024,
            cpu_limit=f"{(target.cpu_millis or 1000) / 1000:g}",
            host_tcp_port=target.host_port,
            container_tcp_port=target.container_tcp_port,
        )

    def _container_target(
        self,
        target: EphemeralContainerTarget,
        *,
        require_material: bool,
    ) -> EphemeralDockerContainerTarget:
        if target.full_container_id is None:
            raise BrokerError(
                "resource_identity_unavailable",
                "Ephemeral run has no persisted immutable container ID.",
            )
        return EphemeralDockerContainerTarget(
            identity=_identity(target),
            full_container_id=target.full_container_id,
            secret_mount=self._secret_mount_for_target(
                target, require_material=require_material
            ),
            image_ref=target.image_ref,
        )

    def _provision_secret_for_start(
        self, target: EphemeralContainerTarget
    ) -> EphemeralSecretMount | None:
        if target.secret_policy is None:
            return None
        manager = self._require_secret_manager()
        try:
            return manager.provision_for_start(
                peer_uid=target.owner_uid,
                account_id=target.account_id,
                repository_id=target.repo_id,
                template_id=target.template_id,
                run_id=uuid.UUID(target.run_id),
                policy=target.secret_policy,
                expires_at_epoch=target.expires_at_epoch,
                now_epoch=int(self._clock()),
            )
        except EphemeralSecretError as exc:
            raise BrokerError(
                "secret_delivery_unavailable",
                "The broker could not prepare the volatile PostgreSQL credential for this run.",
            ) from exc

    def _secret_mount_for_target(
        self, target: EphemeralContainerTarget, *, require_material: bool
    ) -> EphemeralSecretMount | None:
        if target.secret_policy is None:
            return None
        manager = self._require_secret_manager()
        try:
            return manager.mount_for_run(
                peer_uid=target.owner_uid,
                account_id=target.account_id,
                repository_id=target.repo_id,
                template_id=target.template_id,
                run_id=uuid.UUID(target.run_id),
                policy=target.secret_policy,
                expires_at_epoch=target.expires_at_epoch,
                now_epoch=int(self._clock()),
                require_material=require_material,
            )
        except EphemeralSecretError as exc:
            raise BrokerError(
                "secret_delivery_unavailable",
                "The broker could not resolve the volatile PostgreSQL credential for this run.",
            ) from exc

    def _release_run_secret(self, run_id: str) -> None:
        manager = self._secret_manager
        if manager is None:
            return
        try:
            manager.release_run_secret(run_id=uuid.UUID(run_id))
        except EphemeralSecretError as exc:
            raise BrokerError(
                "secret_delivery_cleanup_failed",
                "The broker could not remove volatile PostgreSQL credential material.",
            ) from exc

    def _require_secret_manager(self) -> VolatileRunSecretManager:
        if self._secret_manager is None:
            raise BrokerError(
                "secret_delivery_unavailable",
                "This broker runtime does not provide volatile PostgreSQL credential delivery.",
            )
        return self._secret_manager


def _target(
    connection: sqlite3.Connection, run_id: str
) -> EphemeralContainerTarget:
    row = connection.execute(
        "SELECT * FROM ephemeral_container_runs WHERE run_id = ?", (run_id,)
    ).fetchone()
    if row is None:
        raise BrokerError(
            "resource_unavailable", "Ephemeral run is unavailable."
        )
    command = tuple(
        str(item["argument"])
        for item in connection.execute(
            "SELECT argument FROM ephemeral_run_arguments WHERE run_id = ? ORDER BY ordinal",
            (run_id,),
        )
    )
    environment = tuple(
        (str(item["name"]), str(item["value"]))
        for item in connection.execute(
            "SELECT name, value FROM ephemeral_run_environment WHERE run_id = ? ORDER BY name",
            (run_id,),
        )
    )
    return EphemeralContainerTarget(
        run_id=str(row["run_id"]),
        template_id=str(row["template_id"]),
        repo_id=str(row["repo_id"]),
        owner_uid=int(row["owner_uid"]),
        account_id=str(row["account_id"]),
        creation_nonce=str(row["creation_nonce"]),
        container_name=str(row["container_name"]),
        image_ref=str(row["image_ref"]),
        secret_policy=_secret_policy_from_row(row),
        command=command,
        environment=environment,
        memory_bytes=(
            None if row["memory_bytes"] is None else int(row["memory_bytes"])
        ),
        cpu_millis=(None if row["cpu_millis"] is None else int(row["cpu_millis"])),
        container_tcp_port=(
            None
            if row["container_tcp_port"] is None
            else int(row["container_tcp_port"])
        ),
        host_port_start=(
            None if row["host_port_start"] is None else int(row["host_port_start"])
        ),
        host_port_end=(
            None if row["host_port_end"] is None else int(row["host_port_end"])
        ),
        host_port=(None if row["host_port"] is None else int(row["host_port"])),
        lease_id=(None if row["lease_id"] is None else str(row["lease_id"])),
        full_container_id=(
            None
            if row["full_container_id"] is None
            else str(row["full_container_id"])
        ),
        docker_resource_id=(
            None
            if row["docker_resource_id"] is None
            else str(row["docker_resource_id"])
        ),
        template_fingerprint=str(row["template_fingerprint"]),
        max_ttl_seconds=int(row["max_ttl_seconds"]),
        expires_at_epoch=int(row["expires_at_epoch"]),
        credential_renewal_phase=str(row["credential_renewal_phase"]),
        credential_renewal_old_expires_at_epoch=(
            None
            if row["credential_renewal_old_expires_at_epoch"] is None
            else int(row["credential_renewal_old_expires_at_epoch"])
        ),
        credential_renewal_new_expires_at_epoch=(
            None
            if row["credential_renewal_new_expires_at_epoch"] is None
            else int(row["credential_renewal_new_expires_at_epoch"])
        ),
        credential_renewal_operation_id=(
            None
            if row["credential_renewal_operation_id"] is None
            else str(row["credential_renewal_operation_id"])
        ),
        next_reconcile_at_epoch=int(row["next_reconcile_at_epoch"]),
        recovery_failures=int(row["recovery_failures"]),
        cleanup_requested=bool(row["cleanup_requested"]),
        cleanup_reason=(
            None if row["cleanup_reason"] is None else str(row["cleanup_reason"])
        ),
        error_code=(None if row["error_code"] is None else str(row["error_code"])),
        error_message=(
            None if row["error_message"] is None else str(row["error_message"])
        ),
        status=str(row["status"]),
        phase=str(row["phase"]),
    )


def _identity(target: EphemeralContainerTarget) -> EphemeralDockerIdentity:
    return EphemeralDockerIdentity(
        run_id=target.run_id,
        creation_nonce=target.creation_nonce,
        repository_id=target.repo_id,
        template_id=target.template_id,
        definition_fingerprint=target.template_fingerprint,
    )


def _secret_policy_from_row(row: sqlite3.Row) -> EphemeralSecretPolicy | None:
    """Decode only the non-secret policy/binding snapshot retained on a run."""

    kind = row["secret_policy_kind"]
    binding_id = row["secret_binding_id"]
    if kind is None and binding_id is None:
        return None
    if kind is None or binding_id is None:
        raise BrokerError(
            "secret_policy_snapshot_invalid",
            "Ephemeral run has an incomplete credential-policy snapshot.",
        )
    try:
        return EphemeralSecretPolicy(kind=str(kind), binding_id=str(binding_id))
    except (TypeError, ValueError) as exc:
        raise BrokerError(
            "secret_policy_snapshot_invalid",
            "Ephemeral run has an invalid credential-policy snapshot.",
        ) from exc


def _public_target(target: EphemeralContainerTarget) -> dict[str, Any]:
    return {
        "run_id": target.run_id,
        "template_id": target.template_id,
        "project_id": target.repo_id,
        "container_name": target.container_name,
        "full_container_id": target.full_container_id,
        "status": target.status,
        "phase": target.phase,
        "host_port": target.host_port,
        "container_tcp_port": target.container_tcp_port,
        "expires_at_epoch": target.expires_at_epoch,
        "expires_at": utc_timestamp(target.expires_at_epoch),
        "ownership": "precommitted_nonce_and_exact_labels",
    }


def _phase(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    phase: str,
    status: str,
    recorded_at: str,
    evidence: Mapping[str, Any] | None = None,
    error: Mapping[str, Any] | None = None,
) -> None:
    connection.execute(
        """
        INSERT INTO ephemeral_run_phases(
            run_id, phase, status, evidence_json, error_json, recorded_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            phase,
            status,
            _json(evidence) if evidence is not None else None,
            _json(error) if error is not None else None,
            recorded_at,
        ),
    )
    connection.execute(
        """
        DELETE FROM ephemeral_run_phases
        WHERE run_id = ? AND sequence NOT IN (
            SELECT sequence FROM ephemeral_run_phases
            WHERE run_id = ? ORDER BY sequence DESC
            LIMIT ?
        )
        """,
        (run_id, run_id, _MAX_EPHEMERAL_PHASE_HISTORY),
    )


def _event(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    repo_id: str,
    operation_id: str | None,
    event_kind: str,
    code: str,
    message: str,
    diagnostic: Mapping[str, Any],
    occurred_at: str,
) -> None:
    connection.execute(
        """
        INSERT INTO events(
            event_id, repo_id, source_id, operation_id, event_kind,
            code, message, diagnostic_json, occurred_at
        ) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(uuid.uuid4()),
            repo_id,
            operation_id,
            event_kind,
            code,
            message,
            _json({"run_id": run_id, **dict(diagnostic)}),
            occurred_at,
        ),
    )


def _full_id(value: Any) -> str:
    normalized = str(value or "").lower()
    if _FULL_CONTAINER_ID.fullmatch(normalized) is None:
        raise BrokerBackendError(
            "ephemeral_docker_identity_invalid",
            "Docker did not return one full immutable container ID.",
        )
    return normalized


def _json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        dict(value),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
