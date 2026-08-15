"""System and offline runtime-control API."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Request

from aegishunt.api.contracts import (
    ReplayStatistics,
    RuntimeJobDetail,
    RuntimeJobPage,
    RuntimeMutationRequest,
    RuntimeOverview,
    RuntimeRunOnceRequest,
    RuntimeRunOnceResult,
    RuntimeWorkerPage,
    SystemStatus,
)
from aegishunt.api.dependencies import (
    PaginationDependency,
    get_database,
    get_runtime_service,
    get_settings,
)
from aegishunt.api.errors import not_found
from aegishunt.api.replay_statistics import ReplayStatisticsReader
from aegishunt.api.runtime_observability import RuntimeObservabilityReader
from aegishunt.config import ApplicationSettings
from aegishunt.metadata import APPLICATION_NAME, __version__
from aegishunt.runtime.config import load_runtime_policy
from aegishunt.runtime.contracts import RuntimeJob, RuntimeJobStatus, RuntimeWorker
from aegishunt.runtime.repositories import RuntimeJobRepository, RuntimeWorkerRepository
from aegishunt.runtime.service import RuntimeJobService
from aegishunt.runtime.status import RuntimeStatusReader
from aegishunt.runtime.worker import RuntimeWorkerProcess
from aegishunt.storage import Database
from aegishunt.storage.repositories import AuditLogRepository

router = APIRouter(tags=["system", "runtime"])
DatabaseDependency = Annotated[Database, Depends(get_database)]
RuntimeDependency = Annotated[RuntimeJobService, Depends(get_runtime_service)]
SettingsDependency = Annotated[ApplicationSettings, Depends(get_settings)]
RunOnceOutcome = Literal[
    "job_claimed_by_request_worker",
    "job_already_claimed_by_another_worker",
    "job_queued_after_cycle",
    "no_queued_job",
]


def _runtime_job_observation(
    database: Database,
) -> tuple[int, int, RuntimeJob | None]:
    """Read counts and one related job in a single database snapshot."""

    with database.session() as session:
        jobs = RuntimeJobRepository(session)
        queue_length = jobs.count_by_status(RuntimeJobStatus.QUEUED)
        running_jobs = jobs.count_by_status(
            RuntimeJobStatus.VALIDATING,
            RuntimeJobStatus.RUNNING,
            RuntimeJobStatus.PAUSE_REQUESTED,
        )
        queued, _ = jobs.list(limit=1, status=RuntimeJobStatus.QUEUED)
        if queued:
            return queue_length, running_jobs, queued[0]
        active = tuple(
            job
            for status in (
                RuntimeJobStatus.VALIDATING,
                RuntimeJobStatus.RUNNING,
                RuntimeJobStatus.PAUSE_REQUESTED,
            )
            if (job := jobs.latest_with_status(status)) is not None
        )
        related_job = (
            None
            if not active
            else max(active, key=lambda job: (job.updated_at, str(job.job_id)))
        )
        return queue_length, running_jobs, related_job


def _runtime_job(database: Database, job_id: UUID) -> RuntimeJob | None:
    """Reload one related job after another worker may have changed its state."""

    with database.session() as session:
        return RuntimeJobRepository(session).get(job_id)


def _run_once_outcome(
    *,
    claimed: bool,
    queue_length_before: int,
    running_jobs_before: int,
    queue_length_after: int,
    running_jobs_after: int,
) -> RunOnceOutcome:
    """Distinguish an empty queue from another worker winning the claim race."""

    if claimed:
        return "job_claimed_by_request_worker"
    if queue_length_before > 0 or running_jobs_before > 0 or running_jobs_after > 0:
        return "job_already_claimed_by_another_worker"
    if queue_length_after > 0:
        return "job_queued_after_cycle"
    return "no_queued_job"


@router.get(
    "/system/status",
    response_model=SystemStatus,
    operation_id="get_system_status",
    summary="Get bounded system status",
)
def system_status(request: Request, database: DatabaseDependency) -> SystemStatus:
    """Return actual database/runtime state and local-prototype security semantics."""

    return SystemStatus(
        application=APPLICATION_NAME,
        version=__version__,
        environment=request.app.state.settings.environment,
        database="ready",
        schema_version=request.app.state.schema_version,
        runtime=RuntimeStatusReader(database).read(),
        authentication="not_implemented_local_single_user",
        phase="12",
    )


@router.get(
    "/runtime/status",
    response_model=RuntimeOverview,
    operation_id="get_runtime_status",
    summary="Get runtime queue and progress semantics",
)
def runtime_status(database: DatabaseDependency) -> RuntimeOverview:
    """Keep observed live progress separate from durable committed evidence."""

    latency, resource = RuntimeObservabilityReader(database).read()
    return RuntimeOverview(
        status=RuntimeStatusReader(database).read(),
        latency=latency,
        resource=resource,
    )


@router.get(
    "/runtime/jobs",
    response_model=RuntimeJobPage,
    operation_id="list_runtime_jobs",
    summary="List runtime jobs",
)
def list_runtime_jobs(
    service: RuntimeDependency,
    pagination: PaginationDependency,
    job_status: RuntimeJobStatus | None = None,
) -> RuntimeJobPage:
    items, total = service.list(
        limit=pagination.limit,
        offset=pagination.offset,
        status=job_status,
    )
    next_offset = (
        pagination.offset + len(items)
        if pagination.offset + len(items) < total
        else None
    )
    return RuntimeJobPage(
        items=items,
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
        next_offset=next_offset,
    )


@router.get(
    "/runtime/jobs/{job_id}",
    response_model=RuntimeJobDetail,
    operation_id="get_runtime_job",
    summary="Get runtime job and attempts",
)
def get_runtime_job(job_id: UUID, service: RuntimeDependency) -> RuntimeJobDetail:
    return RuntimeJobDetail(job=service.get(job_id), attempts=service.attempts(job_id))


@router.get(
    "/runtime/replay-statistics/{source_id}",
    response_model=ReplayStatistics,
    operation_id="get_replay_statistics",
    summary="Get statistics isolated to one source replay",
)
def get_replay_statistics(
    source_id: UUID,
    database: DatabaseDependency,
) -> ReplayStatistics:
    with database.session() as session:
        statistics = ReplayStatisticsReader(session).read(source_id)
    if statistics is None:
        not_found("telemetry source")
    return statistics


@router.get(
    "/runtime/workers",
    response_model=RuntimeWorkerPage,
    operation_id="list_runtime_workers",
    summary="List registered runtime workers",
)
def list_runtime_workers(
    database: DatabaseDependency,
    pagination: PaginationDependency,
) -> RuntimeWorkerPage:
    with database.session() as session:
        repository = RuntimeWorkerRepository(session)
        total = repository.count()
        items = repository.list(
            limit=pagination.limit,
            offset=pagination.offset,
        )
    return RuntimeWorkerPage(
        items=items,
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
        next_offset=(
            pagination.offset + len(items)
            if pagination.offset + len(items) < total
            else None
        ),
    )


@router.post(
    "/runtime/workers/run-once",
    response_model=RuntimeRunOnceResult,
    operation_id="run_runtime_worker_once",
    summary="Claim and execute at most one queued replay job",
)
def run_runtime_worker_once(
    request: Request,
    payload: RuntimeRunOnceRequest,
    database: DatabaseDependency,
    settings: SettingsDependency,
) -> RuntimeRunOnceResult:
    """Execute one explicit bounded local worker cycle and then stop."""

    (
        queue_length_before,
        running_jobs_before,
        related_job_before,
    ) = _runtime_job_observation(database)
    request_id = str(request.state.request_id).lower()
    worker_id = f"{settings.web.web_worker_id_prefix}-{request_id[:24]}"
    process = RuntimeWorkerProcess(
        database,
        settings=settings,
        runtime_policy=load_runtime_policy(settings.runtime.policy_path),
        project_root=Path.cwd(),
        worker_id=worker_id,
    )
    claimed = process.run_one_and_stop()
    (
        queue_length_after,
        running_jobs_after,
        related_job_after,
    ) = _runtime_job_observation(database)
    if process.last_claimed_job_id is not None:
        related_job = _runtime_job(database, process.last_claimed_job_id)
    elif related_job_before is not None:
        related_job = _runtime_job(database, related_job_before.job_id)
    else:
        related_job = related_job_after
    outcome = _run_once_outcome(
        claimed=claimed,
        queue_length_before=queue_length_before,
        running_jobs_before=running_jobs_before,
        queue_length_after=queue_length_after,
        running_jobs_after=running_jobs_after,
    )
    with database.session() as session, session.begin():
        worker = RuntimeWorkerRepository(session).get(worker_id)
        if worker is None:
            not_found("runtime worker")
        AuditLogRepository(session).record(
            actor=payload.actor,
            action="run_runtime_worker_once",
            object_type="runtime_workers",
            object_id=worker_id,
            details={
                "reason": payload.reason,
                "claimed_job": claimed,
                "outcome": outcome,
                "queue_length_before": queue_length_before,
                "running_jobs_before": running_jobs_before,
                "queue_length_after": queue_length_after,
                "running_jobs_after": running_jobs_after,
                "related_job_id": (
                    None if related_job is None else str(related_job.job_id)
                ),
                "related_job_status": (
                    None if related_job is None else related_job.status.value
                ),
                "execution_semantics": "claim_at_most_one_then_stop",
            },
        )
    return RuntimeRunOnceResult(
        claimed_job=claimed,
        outcome=outcome,
        queue_length_before=queue_length_before,
        running_jobs_before=running_jobs_before,
        queue_length_after=queue_length_after,
        running_jobs_after=running_jobs_after,
        job=related_job,
        worker=worker,
    )


@router.get(
    "/runtime/workers/{worker_id}",
    response_model=RuntimeWorker,
    operation_id="get_runtime_worker",
    summary="Get registered runtime worker",
)
def get_runtime_worker(worker_id: str, database: DatabaseDependency) -> RuntimeWorker:
    with database.session() as session:
        worker = RuntimeWorkerRepository(session).get(worker_id)
    if worker is None:
        not_found("runtime worker")
    return worker


@router.post(
    "/runtime/jobs/{job_id}/pause",
    response_model=RuntimeJob,
    operation_id="pause_runtime_job",
    summary="Request runtime pause",
)
def pause_runtime_job(
    job_id: UUID, payload: RuntimeMutationRequest, service: RuntimeDependency
) -> RuntimeJob:
    return service.pause(job_id, actor=payload.actor, reason=payload.reason)


@router.post(
    "/runtime/jobs/{job_id}/resume",
    response_model=RuntimeJob,
    operation_id="resume_runtime_job",
    summary="Resume a paused runtime job",
)
def resume_runtime_job(
    job_id: UUID, payload: RuntimeMutationRequest, service: RuntimeDependency
) -> RuntimeJob:
    return service.resume(job_id, actor=payload.actor, reason=payload.reason)


@router.post(
    "/runtime/jobs/{job_id}/recover",
    response_model=RuntimeJob,
    operation_id="recover_runtime_job",
    summary="Explicitly restart recovery from packet origin",
)
def recover_runtime_job(
    job_id: UUID, payload: RuntimeMutationRequest, service: RuntimeDependency
) -> RuntimeJob:
    return service.recover(job_id, actor=payload.actor, reason=payload.reason)
