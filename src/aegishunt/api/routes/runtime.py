"""System and offline runtime-control API."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request

from aegishunt.api.contracts import (
    RuntimeJobDetail,
    RuntimeJobPage,
    RuntimeMutationRequest,
    RuntimeOverview,
    RuntimeWorkerPage,
    SystemStatus,
)
from aegishunt.api.dependencies import (
    PaginationDependency,
    get_database,
    get_runtime_service,
)
from aegishunt.api.errors import not_found
from aegishunt.metadata import APPLICATION_NAME, __version__
from aegishunt.runtime.contracts import RuntimeJob, RuntimeJobStatus, RuntimeWorker
from aegishunt.runtime.repositories import RuntimeWorkerRepository
from aegishunt.runtime.service import RuntimeJobService
from aegishunt.runtime.status import RuntimeStatusReader
from aegishunt.storage import Database

router = APIRouter(tags=["system", "runtime"])
DatabaseDependency = Annotated[Database, Depends(get_database)]
RuntimeDependency = Annotated[RuntimeJobService, Depends(get_runtime_service)]


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

    return RuntimeOverview(status=RuntimeStatusReader(database).read())


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
