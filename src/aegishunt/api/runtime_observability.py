"""Read-only projections of measured runtime timing and process observations."""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import datetime
from uuid import UUID

from aegishunt.api.contracts import (
    RuntimeLatencySummary,
    RuntimeResourceObservation,
)
from aegishunt.runtime.contracts import RuntimeJob, RuntimeJobStatus, RuntimeResourceSample
from aegishunt.runtime.repositories import (
    RuntimeJobRepository,
    RuntimeResourceRepository,
    RuntimeWorkerRepository,
)
from aegishunt.schemas.base import utc_now
from aegishunt.storage import Database

_PID = re.compile(r"^pid:(?P<pid>[1-9][0-9]*)$")


class RuntimeObservabilityReader:
    """Summarize existing timestamps and samples without synthetic values."""

    def __init__(
        self,
        database: Database,
        *,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._database = database
        self._clock = clock

    def read(
        self,
    ) -> tuple[RuntimeLatencySummary, RuntimeResourceObservation]:
        calculated_at = self._clock()
        with self._database.session() as session:
            jobs = RuntimeJobRepository(session)
            job = jobs.latest_with_status(RuntimeJobStatus.COMPLETED)
            if job is None:
                return (
                    RuntimeLatencySummary(
                        status="unavailable",
                        metric_name="runtime_job_start_to_completion_duration",
                        p50_ms=None,
                        p95_ms=None,
                        observation_count=0,
                        window_start=None,
                        window_end=None,
                        source="runtime_jobs.started_at/completed_at",
                        unit="ms",
                        calculated_at=calculated_at,
                        runtime_job_id=None,
                        unavailable_reason=(
                            "no completed runtime job has both start and completion timestamps"
                        ),
                    ),
                    RuntimeResourceObservation(
                        status="unavailable",
                        worker_id=None,
                        runtime_job_id=None,
                        process_id=None,
                        process_cpu_percent=None,
                        process_rss_bytes=None,
                        active_thread_count=None,
                        captured_at=None,
                        metric_source=(
                            "runtime_resource_samples+runtime_workers.process_identity_summary"
                        ),
                        unavailable_reason=(
                            "no completed runtime job has a persisted process sample"
                        ),
                    ),
                )
            latency = self._latency(job, calculated_at=calculated_at)
            sample = RuntimeResourceRepository(session).latest_for_job(job.job_id)
            resource = self._resource(
                sample,
                RuntimeWorkerRepository(session),
                job_id=job.job_id,
            )
            return latency, resource

    @staticmethod
    def _latency(
        job: RuntimeJob,
        *,
        calculated_at: datetime,
    ) -> RuntimeLatencySummary:
        if job.started_at is None or job.completed_at is None:
            return RuntimeLatencySummary(
                status="unavailable",
                metric_name="runtime_job_start_to_completion_duration",
                p50_ms=None,
                p95_ms=None,
                observation_count=0,
                window_start=job.started_at,
                window_end=job.completed_at,
                source="runtime_jobs.started_at/completed_at",
                unit="ms",
                calculated_at=calculated_at,
                runtime_job_id=job.job_id,
                unavailable_reason=(
                    "latest completed runtime job lacks a complete wall-clock interval"
                ),
            )
        duration_ms = max(
            0.0,
            (job.completed_at - job.started_at).total_seconds() * 1_000.0,
        )
        return RuntimeLatencySummary(
            status="available",
            metric_name="runtime_job_start_to_completion_duration",
            p50_ms=duration_ms,
            p95_ms=duration_ms,
            observation_count=1,
            window_start=job.started_at,
            window_end=job.completed_at,
            source="runtime_jobs.started_at/completed_at",
            unit="ms",
            calculated_at=calculated_at,
            runtime_job_id=job.job_id,
            unavailable_reason=None,
        )

    @staticmethod
    def _resource(
        sample: RuntimeResourceSample | None,
        workers: RuntimeWorkerRepository,
        *,
        job_id: UUID,
    ) -> RuntimeResourceObservation:
        if sample is None:
            return RuntimeResourceObservation(
                status="unavailable",
                worker_id=None,
                runtime_job_id=job_id,
                process_id=None,
                process_cpu_percent=None,
                process_rss_bytes=None,
                active_thread_count=None,
                captured_at=None,
                metric_source=("runtime_resource_samples+runtime_workers.process_identity_summary"),
                unavailable_reason=("latest completed runtime job has no persisted process sample"),
            )
        worker = workers.get(sample.worker_id)
        match = None if worker is None else _PID.fullmatch(worker.process_identity_summary)
        process_id = None if match is None else int(match.group("pid"))
        available = sample.sampler_available and process_id is not None
        reason = None
        if not sample.sampler_available:
            reason = sample.error_code or "resource sampler reported unavailable"
        elif process_id is None:
            reason = "worker process ID is unavailable"
        return RuntimeResourceObservation(
            status="available" if available else "unavailable",
            worker_id=sample.worker_id,
            runtime_job_id=sample.job_id,
            process_id=process_id,
            process_cpu_percent=sample.process_cpu_percent,
            process_rss_bytes=sample.process_rss_bytes,
            active_thread_count=sample.thread_count,
            captured_at=sample.sampled_at,
            metric_source=("runtime_resource_samples+runtime_workers.process_identity_summary"),
            unavailable_reason=reason,
        )
