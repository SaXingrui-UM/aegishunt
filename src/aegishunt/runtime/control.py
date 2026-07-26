"""Cooperative runtime pause, heartbeat, progress, and resource control points."""

from __future__ import annotations

import threading
from uuid import UUID

from sqlalchemy.orm import Session

from aegishunt.runtime.clock import RuntimeClock
from aegishunt.runtime.config import LoadedRuntimePolicy
from aegishunt.runtime.contracts import (
    RuntimeCounters,
    RuntimeJobStatus,
    RuntimeResourceSample,
    RuntimeWorkerStatus,
)
from aegishunt.runtime.errors import ReplayInterrupted, RuntimeReplayError
from aegishunt.runtime.repositories import (
    RuntimeJobRepository,
    RuntimeResourceRepository,
    RuntimeWorkerRepository,
)
from aegishunt.runtime.resources import ProcessResourceSampler
from aegishunt.storage import Database
from aegishunt.storage.repositories import AuditLogRepository


class RuntimeControlMonitor:
    """Persist cooperative controls without owning pipeline output transactions."""

    def __init__(
        self,
        database: Database,
        *,
        runtime_policy: LoadedRuntimePolicy,
        worker_id: str,
        stop_event: threading.Event,
        clock: RuntimeClock,
        resource_sampler: ProcessResourceSampler,
    ) -> None:
        self._database = database
        self._runtime = runtime_policy
        self._worker_id = worker_id
        self._stop = stop_event
        self._clock = clock
        self._resources = resource_sampler
        self._last_heartbeat = clock.monotonic()
        self._last_resource_sample = clock.monotonic()
        self._last_progress_update = clock.monotonic()
        self._last_progress_packet_count = 0

    def check(
        self,
        job_id: UUID,
        counters: RuntimeCounters,
        progress: float,
    ) -> None:
        """Apply pending control actions and periodic observability updates."""

        if self._stop.is_set():
            self.record_observed_progress(job_id, counters, progress)
            raise ReplayInterrupted("worker shutdown requested")
        now_mono = self._clock.monotonic()
        heartbeat_due = (
            now_mono - self._last_heartbeat
            >= self._runtime.policy.worker.heartbeat_interval_seconds
        )
        resource_due = (
            now_mono - self._last_resource_sample
            >= self._runtime.policy.resources.sample_interval_seconds
        )
        progress_due = (
            counters.captured_packets - self._last_progress_packet_count
            >= self._runtime.policy.worker.progress_update_packet_interval
            or now_mono - self._last_progress_update
            >= self._runtime.policy.worker.progress_update_seconds
        )
        with self._database.session() as session, session.begin():
            audit = AuditLogRepository(session)
            jobs = RuntimeJobRepository(session, audit)
            current = jobs.get(job_id)
            if current is None:
                raise RuntimeReplayError("runtime job disappeared during replay")
            observation_due = (
                heartbeat_due
                or resource_due
                or progress_due
                or current.status is RuntimeJobStatus.PAUSE_REQUESTED
            )
            if observation_due:
                current = jobs.update_observed_progress(
                    job_id,
                    worker_id=self._worker_id,
                    counters=counters,
                    progress=progress,
                    now=self._clock.now(),
                )
                self._last_progress_update = now_mono
                self._last_progress_packet_count = counters.captured_packets
            if current.status is RuntimeJobStatus.PAUSE_REQUESTED:
                current = jobs.mark_paused(
                    job_id,
                    worker_id=self._worker_id,
                    now=self._clock.now(),
                    actor=self._worker_id,
                )
            if heartbeat_due:
                heartbeat_now = self._clock.now()
                current = jobs.heartbeat(
                    job_id,
                    worker_id=self._worker_id,
                    now=heartbeat_now,
                    lease_seconds=self._runtime.policy.worker.lease_seconds,
                )
                worker_repository = RuntimeWorkerRepository(session)
                worker = worker_repository.get(self._worker_id)
                if worker is not None:
                    worker_repository.upsert(
                        worker.model_copy(update={"heartbeat_at": heartbeat_now})
                    )
                self._last_heartbeat = now_mono
            if resource_due:
                self._sample_resources(session, jobs, job_id)
                self._last_resource_sample = now_mono
        current_status = self._wait_while_paused(job_id, current.status)
        if current_status is not RuntimeJobStatus.RUNNING:
            raise RuntimeReplayError("runtime job cannot continue in its current state")

    def record_observed_progress(
        self,
        job_id: UUID,
        counters: RuntimeCounters,
        progress: float,
    ) -> None:
        """Persist non-durable live telemetry without changing evidence progress."""

        with self._database.session() as session, session.begin():
            RuntimeJobRepository(
                session,
                AuditLogRepository(session),
            ).update_observed_progress(
                job_id,
                worker_id=self._worker_id,
                counters=counters,
                progress=progress,
                now=self._clock.now(),
            )

    def _sample_resources(
        self,
        session: Session,
        jobs: RuntimeJobRepository,
        job_id: UUID,
    ) -> None:
        worker_repository = RuntimeWorkerRepository(session)
        worker = worker_repository.get(self._worker_id)
        wall_now = self._clock.now()
        heartbeat_age = (
            None
            if worker is None
            else max(0.0, (wall_now - worker.heartbeat_at).total_seconds())
        )
        queue_length = jobs.count_by_status(RuntimeJobStatus.QUEUED)
        active_job_count = jobs.count_by_status(
            RuntimeJobStatus.VALIDATING,
            RuntimeJobStatus.RUNNING,
            RuntimeJobStatus.PAUSE_REQUESTED,
            RuntimeJobStatus.PAUSED,
        )
        model_load_state = "not_loaded" if worker is None else worker.model_load_state
        try:
            sample = self._resources.sample(
                worker_id=self._worker_id,
                job_id=job_id,
                queue_length=queue_length,
                active_job_count=active_job_count,
                worker_heartbeat_age_seconds=heartbeat_age,
                model_load_state=model_load_state,
            )
        except (AttributeError, OSError, RuntimeError, ValueError):
            sample = RuntimeResourceSample(
                worker_id=self._worker_id,
                job_id=job_id,
                sampled_at=wall_now,
                queue_length=queue_length,
                active_job_count=active_job_count,
                worker_heartbeat_age_seconds=heartbeat_age,
                model_load_state=model_load_state,
                sampler_available=False,
                monitoring_status="unavailable",
                error_code="resource_sampler_unavailable",
            )
        RuntimeResourceRepository(session).add_and_prune(
            sample,
            retain=self._runtime.policy.resources.retention_samples_per_worker,
        )
        if not sample.sampler_available and worker is not None:
            worker_repository.upsert(
                worker.model_copy(
                    update={
                        "status": RuntimeWorkerStatus.DEGRADED,
                        "degraded_reason": "resource sampler unavailable",
                        "heartbeat_at": self._clock.now(),
                    }
                )
            )

    def _wait_while_paused(
        self,
        job_id: UUID,
        status: RuntimeJobStatus,
    ) -> RuntimeJobStatus:
        current = status
        while current is RuntimeJobStatus.PAUSED:
            if self._stop.is_set():
                raise ReplayInterrupted("worker shutdown requested while paused")
            self._clock.sleep(self._runtime.policy.worker.poll_interval_seconds)
            now_mono = self._clock.monotonic()
            heartbeat_due = (
                now_mono - self._last_heartbeat
                >= self._runtime.policy.worker.heartbeat_interval_seconds
            )
            resource_due = (
                now_mono - self._last_resource_sample
                >= self._runtime.policy.resources.sample_interval_seconds
            )
            with self._database.session() as session, session.begin():
                jobs = RuntimeJobRepository(session, AuditLogRepository(session))
                job = jobs.get(job_id)
                if job is None:
                    raise RuntimeReplayError("paused runtime job disappeared")
                if job.status is RuntimeJobStatus.PAUSED:
                    if heartbeat_due:
                        heartbeat_now = self._clock.now()
                        job = jobs.heartbeat(
                            job_id,
                            worker_id=self._worker_id,
                            now=heartbeat_now,
                            lease_seconds=self._runtime.policy.worker.lease_seconds,
                        )
                        workers = RuntimeWorkerRepository(session)
                        worker = workers.get(self._worker_id)
                        if worker is not None:
                            workers.upsert(
                                worker.model_copy(update={"heartbeat_at": heartbeat_now})
                            )
                        self._last_heartbeat = now_mono
                    if resource_due:
                        self._sample_resources(session, jobs, job_id)
                        self._last_resource_sample = now_mono
                elif job.status is not RuntimeJobStatus.RUNNING:
                    raise RuntimeReplayError(
                        "paused runtime job entered an invalid state"
                    )
                current = job.status
        return current
