"""Runtime job state transitions and explicit recovery semantics."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import select

from aegishunt.runtime.contracts import (
    RuntimeAttemptStatus,
    RuntimeCounters,
    RuntimeDesiredAction,
    RuntimeJob,
    RuntimeJobStatus,
    RuntimeStage,
)
from aegishunt.runtime.errors import RuntimeStateError
from aegishunt.runtime.job_store import RuntimeJobStore, _job
from aegishunt.storage.models.runtime import RuntimeJobRecord


class RuntimeJobRepository(RuntimeJobStore):
    """Apply validated runtime lifecycle transitions."""

    def request_pause(
        self,
        job_id: UUID,
        *,
        actor: str,
        now: datetime,
        reason: str = "operator requested pause",
    ) -> RuntimeJob:
        row = self._required(job_id)
        if row.status is RuntimeJobStatus.PAUSE_REQUESTED:
            return _job(row)
        if row.status is not RuntimeJobStatus.RUNNING:
            raise RuntimeStateError("only a running replay can request pause")
        row.status = RuntimeJobStatus.PAUSE_REQUESTED
        row.desired_action = RuntimeDesiredAction.PAUSE
        row.updated_at = now
        self._session.flush()
        self._record(
            actor=actor,
            action="runtime_pause_requested",
            row=row,
            details={
                "previous_status": "running",
                "status": "pause_requested",
                "reason": reason,
            },
        )
        return _job(row)

    def mark_paused(
        self,
        job_id: UUID,
        *,
        worker_id: str,
        now: datetime,
        actor: str,
    ) -> RuntimeJob:
        row = self._owned(job_id, worker_id)
        if row.status is not RuntimeJobStatus.PAUSE_REQUESTED:
            raise RuntimeStateError("runtime job does not have a pause request")
        row.status = RuntimeJobStatus.PAUSED
        row.updated_at = now
        self._set_attempt(row, RuntimeAttemptStatus.PAUSED, now=now)
        self._session.flush()
        self._record(
            actor=actor,
            action="runtime_paused",
            row=row,
            details={
                "previous_status": "pause_requested",
                "status": "paused",
                "worker_id": worker_id,
            },
        )
        return _job(row)

    def resume(
        self,
        job_id: UUID,
        *,
        actor: str,
        now: datetime,
        reason: str = "operator requested resume",
    ) -> RuntimeJob:
        row = self._required(job_id)
        if row.status is not RuntimeJobStatus.PAUSED or row.claimed_by is None:
            raise RuntimeStateError("only a live worker's paused replay can resume")
        self._record(
            actor=actor,
            action="runtime_resume_requested",
            row=row,
            details={
                "previous_status": "paused",
                "reason": reason,
            },
        )
        row.status = RuntimeJobStatus.RUNNING
        row.desired_action = RuntimeDesiredAction.RUN
        row.updated_at = now
        self._set_attempt(row, RuntimeAttemptStatus.RUNNING, now=now)
        self._session.flush()
        self._record(
            actor=actor,
            action="runtime_resumed",
            row=row,
            details={
                "previous_status": "paused",
                "status": "running",
                "worker_id": row.claimed_by,
                "reason": reason,
            },
        )
        return _job(row)

    def complete(
        self,
        job_id: UUID,
        *,
        worker_id: str,
        counters: RuntimeCounters,
        now: datetime,
        actor: str,
    ) -> RuntimeJob:
        row = self._owned(job_id, worker_id)
        if row.status is not RuntimeJobStatus.RUNNING:
            raise RuntimeStateError("only a running replay can complete")
        row.status = RuntimeJobStatus.COMPLETED
        row.current_stage = RuntimeStage.COMPLETION
        row.desired_action = RuntimeDesiredAction.RUN
        row.counters = counters.model_dump(mode="json")
        row.progress_current = (
            row.progress_total
            if row.progress_total is not None
            else counters.captured_packets
        )
        row.progress = 1.0
        row.updated_at = now
        row.completed_at = now
        self._set_attempt(row, RuntimeAttemptStatus.COMPLETED, now=now, ended=True)
        self._clear_lease(row)
        self._session.flush()
        self._record(
            actor=actor,
            action="runtime_completed",
            row=row,
            details={
                "previous_status": "running",
                "status": "completed",
                "counters": counters.model_dump(mode="json"),
            },
        )
        return _job(row)

    def fail(
        self,
        job_id: UUID,
        *,
        worker_id: str,
        code: str,
        message: str,
        now: datetime,
        actor: str,
        category: str = "pipeline_failure",
        stage: RuntimeStage = RuntimeStage.FAILED,
        retryable: bool = False,
    ) -> RuntimeJob:
        row = self._owned(job_id, worker_id)
        previous_status = row.status.value
        row.status = RuntimeJobStatus.FAILED
        row.current_stage = stage
        row.failure_code = code[:128]
        row.failure_message = message[:1_000]
        row.latest_error_category = category[:128]
        row.latest_error_stage = stage
        row.latest_error_retryable = retryable
        row.latest_error_at = now
        row.updated_at = now
        self._set_attempt(
            row,
            RuntimeAttemptStatus.FAILED,
            now=now,
            ended=True,
            error_code=code,
            error_message=message,
            error_category=category,
            error_retryable=retryable,
        )
        self._clear_lease(row)
        self._session.flush()
        self._record(
            actor=actor,
            action="runtime_failed",
            row=row,
            details={
                "status": "failed",
                "previous_status": previous_status,
                "error_category": category,
                "error_code": code,
                "stage": stage.value,
                "retryable": retryable,
            },
        )
        self._record(
            actor=actor,
            action="runtime_attempt_failure",
            row=row,
            details={
                "status": "failed",
                "previous_status": previous_status,
                "error_category": category,
                "error_code": code,
                "stage": stage.value,
                "retryable": retryable,
            },
        )
        if stage is RuntimeStage.PREFLIGHT:
            self._record(
                actor=actor,
                action="runtime_preflight_failed",
                row=row,
                details={
                    "status": "failed",
                    "previous_status": previous_status,
                    "error_code": code,
                    "stage": stage.value,
                    "retryable": retryable,
                },
            )
        return _job(row)

    def interrupt(
        self,
        job_id: UUID,
        *,
        worker_id: str,
        reason: str,
        now: datetime,
        actor: str,
    ) -> RuntimeJob:
        row = self._owned(job_id, worker_id)
        previous_status = row.status.value
        row.status = RuntimeJobStatus.RECOVERY_PENDING
        row.current_stage = RuntimeStage.RECOVERY
        row.updated_at = now
        row.failure_code = "interrupted"
        row.failure_message = reason[:1_000]
        row.latest_error_category = "worker_interrupted"
        row.latest_error_stage = RuntimeStage.REPLAY
        row.latest_error_retryable = True
        row.latest_error_at = now
        self._set_attempt(
            row,
            RuntimeAttemptStatus.INTERRUPTED,
            now=now,
            ended=True,
            interruption_reason=reason,
            error_category="worker_interrupted",
            error_code="interrupted",
            error_message=reason,
            error_retryable=True,
        )
        self._clear_lease(row)
        self._session.flush()
        self._record(
            actor=actor,
            action="runtime_interrupted",
            row=row,
            details={
                "status": "recovery_pending",
                "previous_status": previous_status,
                "reason": reason,
                "recovery_strategy": "deterministic_restart_from_origin",
            },
        )
        return _job(row)

    def recover(
        self,
        job_id: UUID,
        *,
        actor: str,
        now: datetime,
        reason: str = "operator requested explicit origin recovery",
        maximum_attempts: int = 100,
    ) -> RuntimeJob:
        row = self._required(job_id)
        if row.status not in {RuntimeJobStatus.RECOVERY_PENDING, RuntimeJobStatus.FAILED}:
            raise RuntimeStateError("only failed or recovery-pending jobs can be recovered")
        if (
            row.status is RuntimeJobStatus.FAILED
            and row.latest_error_retryable is not True
        ):
            raise RuntimeStateError("permanent runtime failures cannot be recovered")
        if row.current_attempt_number >= maximum_attempts:
            raise RuntimeStateError("runtime job has reached the configured attempt limit")
        previous = row.status
        row.status = RuntimeJobStatus.QUEUED
        row.desired_action = RuntimeDesiredAction.RUN
        row.current_stage = RuntimeStage.QUEUED
        row.progress = 0.0
        row.progress_current = 0
        row.counters = RuntimeCounters().model_dump(mode="json")
        row.current_attempt_id = None
        row.recovery_count += 1
        row.updated_at = now
        self._clear_lease(row)
        self._session.flush()
        self._record(
            actor=actor,
            action="runtime_recovery_requested",
            row=row,
            details={
                "previous_status": previous.value,
                "status": "queued",
                "strategy": "deterministic_restart_from_origin",
                "reason": reason,
                "previous_error_code": row.failure_code,
            },
        )
        return _job(row)

    def reconcile_stale(self, *, now: datetime, actor: str) -> tuple[RuntimeJob, ...]:
        rows = self._session.scalars(
            select(RuntimeJobRecord)
            .where(
                RuntimeJobRecord.status.in_(
                    (
                        RuntimeJobStatus.VALIDATING,
                        RuntimeJobStatus.RUNNING,
                        RuntimeJobStatus.PAUSE_REQUESTED,
                        RuntimeJobStatus.PAUSED,
                    )
                ),
                RuntimeJobRecord.lease_expires_at < now,
            )
            .order_by(RuntimeJobRecord.job_id)
        ).all()
        output: list[RuntimeJob] = []
        for row in rows:
            previous_worker = row.claimed_by
            previous_status = row.status.value
            row.status = RuntimeJobStatus.RECOVERY_PENDING
            row.current_stage = RuntimeStage.RECOVERY
            row.failure_code = "stale_worker_lease"
            row.failure_message = "worker lease expired; explicit recovery is required"
            row.latest_error_category = "worker_interrupted"
            row.latest_error_stage = RuntimeStage.REPLAY
            row.latest_error_retryable = True
            row.latest_error_at = now
            row.updated_at = now
            self._set_attempt(
                row,
                RuntimeAttemptStatus.INTERRUPTED,
                now=now,
                ended=True,
                interruption_reason="worker lease expired",
                error_category="worker_interrupted",
                error_code="stale_worker_lease",
                error_message="worker lease expired; explicit recovery is required",
                error_retryable=True,
            )
            self._clear_lease(row)
            self._session.flush()
            self._record(
                actor=actor,
                action="runtime_stale_reconciled",
                row=row,
                details={
                    "previous_worker_id": previous_worker,
                    "previous_status": previous_status,
                    "status": "recovery_pending",
                    "automatic_recovery": False,
                },
            )
            output.append(_job(row))
        return tuple(output)
