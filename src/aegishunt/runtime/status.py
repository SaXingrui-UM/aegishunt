"""Read-only runtime health/status boundary for CLI and Phase 11 frontend shell."""

from __future__ import annotations

from aegishunt.runtime.contracts import (
    RuntimeJobStatus,
    RuntimeStatus,
)
from aegishunt.runtime.repositories import (
    RuntimeJobRepository,
    RuntimeResourceRepository,
    RuntimeWorkerRepository,
)
from aegishunt.schemas.base import JsonObject
from aegishunt.storage import Database


class RuntimeStatusReader:
    """Return bounded queue, worker, resource, and safe error status."""

    def __init__(self, database: Database) -> None:
        self._database = database

    def read(self) -> RuntimeStatus:
        with self._database.session() as session:
            jobs = RuntimeJobRepository(session)
            failed, _ = jobs.list(limit=10, status=RuntimeJobStatus.FAILED)
            recovery, _ = jobs.list(limit=10, status=RuntimeJobStatus.RECOVERY_PENDING)
            latest_errors: tuple[JsonObject, ...] = tuple(
                {
                    "job_id": str(job.job_id),
                    "status": job.status.value,
                    "error_code": job.failure_code,
                    "error_message": job.failure_message,
                    "error_category": job.latest_error_category,
                    "error_stage": (
                        None
                        if job.latest_error_stage is None
                        else job.latest_error_stage.value
                    ),
                    "retryable": job.latest_error_retryable,
                    "updated_at": job.updated_at.isoformat(),
                }
                for job in sorted(
                    (*failed, *recovery),
                    key=lambda item: (item.updated_at, item.job_id),
                    reverse=True,
                )[:10]
            )
            return RuntimeStatus(
                queue_length=jobs.count_by_status(RuntimeJobStatus.QUEUED),
                recovery_pending=jobs.count_by_status(
                    RuntimeJobStatus.RECOVERY_PENDING
                ),
                running_jobs=jobs.count_by_status(
                    RuntimeJobStatus.VALIDATING,
                    RuntimeJobStatus.RUNNING,
                    RuntimeJobStatus.PAUSE_REQUESTED,
                ),
                paused_jobs=jobs.count_by_status(RuntimeJobStatus.PAUSED),
                latest_jobs=jobs.latest(limit=10),
                workers=tuple(RuntimeWorkerRepository(session).list()),
                latest_samples=RuntimeResourceRepository(session).latest(),
                latest_errors=latest_errors,
                model_loading_state="verified_per_job_preflight",
                live_capture_enabled=False,
                automatic_recovery=False,
            )
