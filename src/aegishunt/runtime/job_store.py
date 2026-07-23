"""Durable runtime job storage, claims, progress, and audit helpers."""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from aegishunt.runtime.contracts import (
    RuntimeAttempt,
    RuntimeAttemptStatus,
    RuntimeCounters,
    RuntimeDesiredAction,
    RuntimeJob,
    RuntimeJobStatus,
    RuntimeStage,
)
from aegishunt.runtime.errors import RuntimeClaimError, RuntimeStateError
from aegishunt.schemas.base import JsonObject
from aegishunt.storage.models.runtime import (
    RuntimeAttemptRecord,
    RuntimeJobRecord,
)
from aegishunt.storage.repositories.audit import AuditLogRepository


def _job(row: RuntimeJobRecord) -> RuntimeJob:
    return RuntimeJob.model_validate(row)


def _attempt(row: RuntimeAttemptRecord) -> RuntimeAttempt:
    return RuntimeAttempt.model_validate(row)


class RuntimeJobStore:
    """Own runtime state transitions while callers own transaction boundaries."""

    def __init__(self, session: Session, audit: AuditLogRepository | None = None) -> None:
        self._session = session
        self._audit = audit

    def add(self, job: RuntimeJob, *, actor: str) -> RuntimeJob:
        values = job.model_dump(mode="python")
        values["snapshot"] = job.snapshot.model_dump(mode="json")
        values["counters"] = job.counters.model_dump(mode="json")
        row = RuntimeJobRecord(**values)
        self._session.add(row)
        self._session.flush()
        self._record(
            actor=actor,
            action="runtime_job_create",
            row=row,
            details={"status": job.status.value, "source_id": str(job.source_id)},
        )
        return _job(row)

    def get(self, job_id: UUID) -> RuntimeJob | None:
        row = self._session.get(RuntimeJobRecord, job_id)
        return None if row is None else _job(row)

    def get_by_source(self, source_id: UUID) -> RuntimeJob | None:
        row = self._session.scalar(
            select(RuntimeJobRecord).where(RuntimeJobRecord.source_id == source_id)
        )
        return None if row is None else _job(row)

    def list(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        status: RuntimeJobStatus | None = None,
    ) -> tuple[list[RuntimeJob], int]:
        query = select(RuntimeJobRecord)
        count = select(func.count(RuntimeJobRecord.job_id))
        if status is not None:
            query = query.where(RuntimeJobRecord.status == status)
            count = count.where(RuntimeJobRecord.status == status)
        rows = self._session.scalars(
            query.order_by(RuntimeJobRecord.created_at, RuntimeJobRecord.job_id)
            .limit(limit)
            .offset(offset)
        ).all()
        total = self._session.scalar(count) or 0
        return [_job(row) for row in rows], total

    def claim_next(
        self,
        *,
        worker_id: str,
        now: datetime,
        lease_seconds: float,
        actor: str,
    ) -> RuntimeJob | None:
        candidate = (
            select(RuntimeJobRecord.job_id)
            .where(RuntimeJobRecord.status == RuntimeJobStatus.QUEUED)
            .order_by(RuntimeJobRecord.created_at, RuntimeJobRecord.job_id)
            .limit(1)
            .scalar_subquery()
        )
        lease_expires = now + timedelta(seconds=lease_seconds)
        result = self._session.execute(
            update(RuntimeJobRecord)
            .where(
                RuntimeJobRecord.job_id == candidate,
                RuntimeJobRecord.status == RuntimeJobStatus.QUEUED,
            )
            .values(
                status=RuntimeJobStatus.VALIDATING,
                desired_action=RuntimeDesiredAction.RUN,
                current_stage=RuntimeStage.PREFLIGHT,
                claimed_by=worker_id,
                heartbeat_at=now,
                lease_expires_at=lease_expires,
                started_at=func.coalesce(RuntimeJobRecord.started_at, now),
                updated_at=now,
            )
            .returning(RuntimeJobRecord.job_id)
        ).scalar_one_or_none()
        if result is None:
            return None
        row = self._required(result)
        self._record(
            actor=actor,
            action="runtime_job_claim",
            row=row,
            details={
                "worker_id": worker_id,
                "previous_status": RuntimeJobStatus.QUEUED.value,
                "status": RuntimeJobStatus.VALIDATING.value,
                "lease_expires_at": lease_expires.isoformat(),
            },
        )
        return _job(row)

    def start_attempt(
        self,
        job_id: UUID,
        *,
        worker_id: str,
        now: datetime,
        actor: str,
        maximum_attempts: int = 100,
    ) -> RuntimeAttempt:
        row = self._owned(job_id, worker_id)
        if row.status is not RuntimeJobStatus.VALIDATING:
            raise RuntimeStateError("attempt can start only while validating")
        number = (
            self._session.scalar(
                select(func.count(RuntimeAttemptRecord.attempt_id)).where(
                    RuntimeAttemptRecord.job_id == job_id
                )
            )
            or 0
        ) + 1
        if number > maximum_attempts:
            raise RuntimeStateError("runtime job has reached the configured attempt limit")
        attempt = RuntimeAttempt(
            job_id=job_id,
            worker_id=worker_id,
            attempt_number=number,
            started_at=now,
            updated_at=now,
            counters=RuntimeCounters.model_validate(row.counters),
            progress_current=row.progress_current,
            progress_total=row.progress_total,
            progress=row.progress,
        )
        attempt_row = RuntimeAttemptRecord(**attempt.model_dump(mode="python"))
        self._session.add(attempt_row)
        row.current_attempt_id = attempt.attempt_id
        row.current_attempt_number = number
        self._session.flush()
        self._record(
            actor=actor,
            action="runtime_attempt_start",
            row=row,
            details={
                "attempt_id": str(attempt.attempt_id),
                "attempt_number": number,
                "restart_from_origin": True,
            },
        )
        return _attempt(attempt_row)

    def mark_running(
        self,
        job_id: UUID,
        *,
        worker_id: str,
        now: datetime,
        actor: str,
    ) -> RuntimeJob:
        row = self._owned(job_id, worker_id)
        if row.status is not RuntimeJobStatus.VALIDATING:
            raise RuntimeStateError("validated job is not in the validating state")
        row.status = RuntimeJobStatus.RUNNING
        row.current_stage = RuntimeStage.REPLAY
        row.updated_at = now
        self._session.flush()
        self._record(
            actor=actor,
            action="runtime_preflight_succeeded",
            row=row,
            details={
                "previous_status": RuntimeJobStatus.VALIDATING.value,
                "status": RuntimeJobStatus.RUNNING.value,
                "stage": RuntimeStage.REPLAY.value,
            },
        )
        return _job(row)

    def heartbeat(
        self,
        job_id: UUID,
        *,
        worker_id: str,
        now: datetime,
        lease_seconds: float,
    ) -> RuntimeJob:
        row = self._owned(job_id, worker_id)
        if row.status not in {
            RuntimeJobStatus.VALIDATING,
            RuntimeJobStatus.RUNNING,
            RuntimeJobStatus.PAUSE_REQUESTED,
            RuntimeJobStatus.PAUSED,
        }:
            raise RuntimeClaimError("runtime job cannot renew a lease in its current state")
        row.heartbeat_at = now
        row.lease_expires_at = now + timedelta(seconds=lease_seconds)
        row.updated_at = now
        self._session.flush()
        return _job(row)

    def update_progress(
        self,
        job_id: UUID,
        *,
        worker_id: str,
        counters: RuntimeCounters,
        progress: float,
        now: datetime,
    ) -> RuntimeJob:
        row = self._owned(job_id, worker_id)
        if row.status not in {
            RuntimeJobStatus.RUNNING,
            RuntimeJobStatus.PAUSE_REQUESTED,
        }:
            raise RuntimeStateError("progress can update only for an active replay")
        if progress < row.progress:
            raise RuntimeStateError("runtime progress cannot decrease within one attempt")
        row.counters = counters.model_dump(mode="json")
        row.progress_current = counters.captured_packets
        row.progress = progress
        row.updated_at = now
        attempt = self._current_attempt(row)
        attempt.counters = counters.model_dump(mode="json")
        attempt.progress_current = row.progress_current
        attempt.progress_total = row.progress_total
        attempt.progress = progress
        attempt.updated_at = now
        self._session.flush()
        return _job(row)

    def set_stage(
        self,
        job_id: UUID,
        *,
        worker_id: str,
        stage: RuntimeStage,
        now: datetime,
        actor: str,
    ) -> RuntimeJob:
        row = self._owned(job_id, worker_id)
        if row.status is not RuntimeJobStatus.RUNNING:
            raise RuntimeStateError("runtime stage can change only while running")
        previous = row.current_stage
        row.current_stage = stage
        row.updated_at = now
        self._session.flush()
        self._record(
            actor=actor,
            action="runtime_stage_change",
            row=row,
            details={"previous_stage": previous.value, "stage": stage.value},
        )
        return _job(row)

    def count_by_status(self, *statuses: RuntimeJobStatus) -> int:
        return (
            self._session.scalar(
                select(func.count(RuntimeJobRecord.job_id)).where(
                    RuntimeJobRecord.status.in_(statuses)
                )
            )
            or 0
        )

    def latest(self, *, limit: int = 10) -> tuple[RuntimeJob, ...]:
        rows = self._session.scalars(
            select(RuntimeJobRecord)
            .order_by(
                RuntimeJobRecord.updated_at.desc(),
                RuntimeJobRecord.job_id.desc(),
            )
            .limit(limit)
        ).all()
        return tuple(_job(row) for row in rows)

    def list_attempts(self, job_id: UUID) -> tuple[RuntimeAttempt, ...]:
        rows = self._session.scalars(
            select(RuntimeAttemptRecord)
            .where(RuntimeAttemptRecord.job_id == job_id)
            .order_by(RuntimeAttemptRecord.attempt_number)
        ).all()
        return tuple(_attempt(row) for row in rows)

    def _required(self, job_id: UUID) -> RuntimeJobRecord:
        row = self._session.get(RuntimeJobRecord, job_id)
        if row is None:
            raise RuntimeStateError("runtime job does not exist")
        return row

    def _owned(self, job_id: UUID, worker_id: str) -> RuntimeJobRecord:
        row = self._required(job_id)
        if row.claimed_by != worker_id:
            raise RuntimeClaimError("runtime job is not owned by this worker")
        return row

    def _set_attempt(
        self,
        row: RuntimeJobRecord,
        status: RuntimeAttemptStatus,
        *,
        now: datetime,
        ended: bool = False,
        interruption_reason: str | None = None,
        error_category: str | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
        error_retryable: bool | None = None,
    ) -> None:
        attempt = self._current_attempt(row)
        attempt.status = status
        attempt.updated_at = now
        attempt.ended_at = now if ended else None
        attempt.paused_at = now if status is RuntimeAttemptStatus.PAUSED else attempt.paused_at
        attempt.resumed_at = (
            now
            if status is RuntimeAttemptStatus.RUNNING and attempt.paused_at is not None
            else attempt.resumed_at
        )
        attempt.interrupted_at = (
            now if status is RuntimeAttemptStatus.INTERRUPTED else attempt.interrupted_at
        )
        attempt.completed_at = (
            now if status is RuntimeAttemptStatus.COMPLETED else attempt.completed_at
        )
        attempt.counters = row.counters
        attempt.progress_current = row.progress_current
        attempt.progress_total = row.progress_total
        attempt.progress = row.progress
        attempt.interruption_reason = interruption_reason
        attempt.error_category = error_category
        attempt.error_code = error_code
        attempt.error_message = None if error_message is None else error_message[:1_000]
        attempt.error_retryable = error_retryable

    def _current_attempt(self, row: RuntimeJobRecord) -> RuntimeAttemptRecord:
        if row.current_attempt_id is None:
            raise RuntimeStateError("runtime job has no current attempt")
        attempt = self._session.get(RuntimeAttemptRecord, row.current_attempt_id)
        if attempt is None:
            raise RuntimeStateError("runtime job references a missing attempt")
        return attempt

    @staticmethod
    def _clear_lease(row: RuntimeJobRecord) -> None:
        row.claimed_by = None
        row.lease_expires_at = None
        row.heartbeat_at = None

    def _record(
        self,
        *,
        actor: str,
        action: str,
        row: RuntimeJobRecord,
        details: JsonObject,
    ) -> None:
        if self._audit is not None:
            enriched = {
                "source_id": str(row.source_id),
                "attempt_id": (
                    None
                    if row.current_attempt_id is None
                    else str(row.current_attempt_id)
                ),
                "attempt_number": row.current_attempt_number,
                "worker_id": row.claimed_by,
                "snapshot_checksum": row.snapshot_checksum,
                "lifecycle_timestamp": row.updated_at.isoformat(),
                "operation_id": f"{action}:{row.job_id}:{row.updated_at.isoformat()}",
                **details,
            }
            self._audit.record(
                actor=actor,
                action=action,
                object_type=RuntimeJobRecord.__tablename__,
                object_id=str(row.job_id),
                details=enriched,
                created_at=row.updated_at,
            )
