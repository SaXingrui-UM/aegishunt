"""Single-process durable worker with explicit lease, recovery, and shutdown behavior."""

from __future__ import annotations

import os
import threading
from pathlib import Path
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError

from aegishunt.config import ApplicationSettings
from aegishunt.errors import AegisHuntError
from aegishunt.runtime.clock import RuntimeClock
from aegishunt.runtime.config import LoadedRuntimePolicy
from aegishunt.runtime.contracts import RuntimeStage, RuntimeWorker, RuntimeWorkerStatus
from aegishunt.runtime.environment import resolve_job_execution_environment
from aegishunt.runtime.errors import (
    ReplayInterrupted,
    RuntimeError,
    RuntimePersistenceError,
    RuntimePreflightError,
)
from aegishunt.runtime.pipeline import RuntimePipelineRunner
from aegishunt.runtime.repositories import (
    RuntimeJobRepository,
    RuntimeWorkerRepository,
)
from aegishunt.runtime.resources import ProcessResourceSampler
from aegishunt.storage import Database
from aegishunt.storage.repositories import AuditLogRepository


class RuntimeWorkerProcess:
    """Claim and execute jobs sequentially on one SQLite-backed node."""

    def __init__(
        self,
        database: Database,
        *,
        settings: ApplicationSettings,
        runtime_policy: LoadedRuntimePolicy,
        project_root: Path,
        worker_id: str,
        stop_event: threading.Event | None = None,
        clock: RuntimeClock | None = None,
        resource_sampler: ProcessResourceSampler | None = None,
    ) -> None:
        self._database = database
        self._settings = settings
        self._runtime = runtime_policy
        self._project_root = project_root
        self._worker_id = worker_id
        self._stop = stop_event or threading.Event()
        self._clock = clock or RuntimeClock()
        self._resource_sampler = resource_sampler
        self._last_claimed_job_id: UUID | None = None

    @property
    def stop_event(self) -> threading.Event:
        return self._stop

    @property
    def last_claimed_job_id(self) -> UUID | None:
        """Return the job identity claimed by the most recent bounded cycle."""

        return self._last_claimed_job_id

    def start(self) -> RuntimeWorker:
        now = self._clock.now()
        worker = RuntimeWorker(
            worker_id=self._worker_id,
            status=RuntimeWorkerStatus.IDLE,
            process_identity_summary=f"pid:{os.getpid()}",
            started_at=now,
            heartbeat_at=now,
        )
        with self._database.session() as session, session.begin():
            workers = RuntimeWorkerRepository(session)
            workers.reconcile_stale(
                now=now,
                stale_after_seconds=self._runtime.policy.worker.stale_after_seconds,
            )
            stored = workers.upsert(worker)
            RuntimeJobRepository(
                session,
                AuditLogRepository(session),
            ).reconcile_stale(now=now, actor=self._worker_id)
            return stored

    def run_once(self) -> bool:
        """Run at most one queued job; return whether a claim was made."""

        self._last_claimed_job_id = None
        if self._stop.is_set():
            return False
        now = self._clock.now()
        with self._database.session() as session, session.begin():
            worker_repository = RuntimeWorkerRepository(session)
            existing = worker_repository.get(self._worker_id)
            if existing is None:
                raise RuntimeError("runtime worker must be started before claiming jobs")
            jobs = RuntimeJobRepository(session, AuditLogRepository(session))
            job = jobs.claim_next(
                worker_id=self._worker_id,
                now=now,
                lease_seconds=self._runtime.policy.worker.lease_seconds,
                actor=self._worker_id,
            )
            if job is None:
                worker_repository.upsert(
                    existing.model_copy(
                        update={
                            "status": RuntimeWorkerStatus.IDLE,
                            "current_job_id": None,
                            "heartbeat_at": now,
                            "degraded_reason": existing.degraded_reason,
                        }
                    )
                )
                return False
            self._last_claimed_job_id = job.job_id
            attempt = jobs.start_attempt(
                job.job_id,
                worker_id=self._worker_id,
                now=now,
                actor=self._worker_id,
                maximum_attempts=self._runtime.policy.worker.maximum_attempts,
            )
            claimed = jobs.get(job.job_id)
            if claimed is None or claimed.current_attempt_id != attempt.attempt_id:
                raise RuntimeError("runtime attempt was not bound to its claimed job")
            worker_repository.upsert(
                existing.model_copy(
                    update={
                        "status": RuntimeWorkerStatus.BUSY,
                        "current_job_id": job.job_id,
                        "heartbeat_at": now,
                        "stopped_at": None,
                    }
                )
            )
            job = claimed
        try:
            environment = resolve_job_execution_environment(
                self._settings,
                job.snapshot,
                project_root=self._project_root,
            )
            runner = RuntimePipelineRunner(
                self._database,
                settings=environment.settings,
                runtime_policy=environment.runtime_policy,
                project_root=self._project_root,
                worker_id=self._worker_id,
                stop_event=self._stop,
                clock=self._clock,
                resource_sampler=self._resource_sampler,
            )
            runner.run(job)
        except ReplayInterrupted as exc:
            self._interrupt(job.job_id, str(exc))
        except AegisHuntError as exc:
            self._fail(job.job_id, exc)
        except SQLAlchemyError as exc:
            persistence_error = RuntimePersistenceError(
                "runtime heartbeat or control persistence failed"
            )
            try:
                self._fail(job.job_id, persistence_error)
            except SQLAlchemyError:
                raise persistence_error from exc
        finally:
            self._set_idle_or_stopped()
        return True

    def run_forever(self) -> None:
        self.start()
        try:
            while not self._stop.is_set():
                claimed = self.run_once()
                if not claimed:
                    self._clock.sleep(self._runtime.policy.worker.poll_interval_seconds)
        finally:
            self._set_stopped()

    def run_one_and_stop(self) -> bool:
        """Start, claim at most one job, then persist a stopped worker state."""

        self.start()
        try:
            return self.run_once()
        finally:
            self._set_stopped()

    def request_shutdown(self) -> None:
        """Signal handlers call only this setter."""

        self._stop.set()

    def _interrupt(self, job_id: UUID, reason: str) -> None:
        with self._database.session() as session, session.begin():
            RuntimeJobRepository(
                session,
                AuditLogRepository(session),
            ).interrupt(
                job_id,
                worker_id=self._worker_id,
                reason=reason,
                now=self._clock.now(),
                actor=self._worker_id,
            )

    def _fail(self, job_id: UUID, error: AegisHuntError) -> None:
        code = error.__class__.__name__.removesuffix("Error").lower() or "runtime_failure"
        if isinstance(error, RuntimePreflightError):
            category = "pipeline_preflight"
            stage = RuntimeStage.PREFLIGHT
            retryable = False
        elif isinstance(error, RuntimePersistenceError):
            category = "database_temporarily_unavailable"
            stage = RuntimeStage.REPLAY
            retryable = True
        else:
            category = "pipeline_replay"
            stage = RuntimeStage.REPLAY
            retryable = False
        with self._database.session() as session, session.begin():
            RuntimeJobRepository(
                session,
                AuditLogRepository(session),
            ).fail(
                job_id,
                worker_id=self._worker_id,
                code=code,
                message=str(error),
                category=category,
                stage=stage,
                retryable=retryable,
                now=self._clock.now(),
                actor=self._worker_id,
            )

    def _set_idle_or_stopped(self) -> None:
        now = self._clock.now()
        try:
            with self._database.session() as session, session.begin():
                repository = RuntimeWorkerRepository(session)
                worker = repository.get(self._worker_id)
                if worker is None:
                    return
                status = (
                    RuntimeWorkerStatus.STOPPING
                    if self._stop.is_set()
                    else (
                        RuntimeWorkerStatus.DEGRADED
                        if worker.degraded_reason is not None
                        else RuntimeWorkerStatus.IDLE
                    )
                )
                repository.upsert(
                    worker.model_copy(
                        update={
                            "status": status,
                            "current_job_id": None,
                            "heartbeat_at": now,
                        }
                    )
                )
        except SQLAlchemyError as exc:
            raise RuntimePersistenceError(
                "runtime worker status could not be persisted"
            ) from exc

    def _set_stopped(self) -> None:
        now = self._clock.now()
        try:
            with self._database.session() as session, session.begin():
                repository = RuntimeWorkerRepository(session)
                worker = repository.get(self._worker_id)
                if worker is None:
                    return
                repository.upsert(
                    worker.model_copy(
                        update={
                            "status": RuntimeWorkerStatus.STOPPED,
                            "current_job_id": None,
                            "heartbeat_at": now,
                            "stopped_at": now,
                        }
                    )
                )
        except SQLAlchemyError as exc:
            raise RuntimePersistenceError(
                "runtime worker stop state could not be persisted"
            ) from exc
