"""Telemetry upload, sample, and durable ingestion-job endpoints."""

from __future__ import annotations

import logging
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy.exc import SQLAlchemyError

from aegishunt.api.dependencies import get_ingestion_service
from aegishunt.errors import DatabaseError
from aegishunt.ingestion.errors import (
    IngestionError,
    IngestionJobFailedError,
    IngestionJobNotFoundError,
)
from aegishunt.ingestion.schemas import IngestionJob, IngestionJobPage, SampleDescriptor
from aegishunt.ingestion.service import IngestionService
from aegishunt.schemas.enums import SourceType

router = APIRouter(prefix="/ingestion", tags=["ingestion"])
logger = logging.getLogger(__name__)
ServiceDependency = Annotated[IngestionService, Depends(get_ingestion_service)]
UploadDependency = Annotated[UploadFile, File(description="Bounded telemetry upload")]


def _operator_error(error: IngestionError) -> HTTPException:
    detail: dict[str, str] = {"code": error.code, "message": str(error)}
    if isinstance(error, IngestionJobFailedError):
        detail["code"] = error.cause.code
        detail["job_id"] = str(error.job_id)
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=detail)


def _database_unavailable(error: DatabaseError | SQLAlchemyError) -> HTTPException:
    """Return a fixed fail-closed response and log no exception details."""

    del error
    logger.error("database operation is unavailable; request was not completed")
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={
            "code": "database_unavailable",
            "message": "database is unavailable; request was not completed",
        },
    )


def _ingest_upload(
    file: UploadFile,
    service: IngestionService,
    source_type: SourceType,
) -> IngestionJob:
    try:
        return service.ingest_stream(
            file.file,
            filename=file.filename or "",
            content_type=file.content_type,
            source_type=source_type,
            actor="api",
        )
    except IngestionError as exc:
        raise _operator_error(exc) from exc
    except (DatabaseError, SQLAlchemyError) as exc:
        raise _database_unavailable(exc) from exc


@router.post("/pcap", response_model=IngestionJob, status_code=status.HTTP_201_CREATED)
def upload_pcap(file: UploadDependency, service: ServiceDependency) -> IngestionJob:
    """Validate and safely store a PCAP container without decoding packets."""

    return _ingest_upload(file, service, SourceType.PCAP)


@router.post("/flow-csv", response_model=IngestionJob, status_code=status.HTTP_201_CREATED)
def upload_flow_csv(file: UploadDependency, service: ServiceDependency) -> IngestionJob:
    """Validate and safely store a canonical flow CSV."""

    return _ingest_upload(file, service, SourceType.FLOW_CSV)


@router.post("/json-events", response_model=IngestionJob, status_code=status.HTTP_201_CREATED)
def upload_json_events(file: UploadDependency, service: ServiceDependency) -> IngestionJob:
    """Validate and safely store structured JSON events."""

    return _ingest_upload(file, service, SourceType.JSON_EVENT)


@router.get("/jobs", response_model=IngestionJobPage)
def list_jobs(
    service: ServiceDependency,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> IngestionJobPage:
    """List durable ingestion jobs with bounded pagination."""

    try:
        return service.list_jobs(limit=limit, offset=offset)
    except (DatabaseError, SQLAlchemyError) as exc:
        raise _database_unavailable(exc) from exc


@router.get("/jobs/{job_id}", response_model=IngestionJob)
def get_job(job_id: UUID, service: ServiceDependency) -> IngestionJob:
    """Return one durable ingestion job."""

    try:
        return service.get_job(job_id)
    except IngestionJobNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc
    except (DatabaseError, SQLAlchemyError) as exc:
        raise _database_unavailable(exc) from exc


@router.get("/samples", response_model=list[SampleDescriptor])
def list_samples(service: ServiceDependency) -> list[SampleDescriptor]:
    """List checksum-declared local demonstration samples."""

    try:
        return service.list_samples()
    except IngestionError as exc:
        raise _operator_error(exc) from exc


@router.post(
    "/samples/{sample_id}",
    response_model=IngestionJob,
    status_code=status.HTTP_201_CREATED,
)
def ingest_sample(sample_id: str, service: ServiceDependency) -> IngestionJob:
    """Validate and ingest one allowlisted, checksum-verified sample."""

    try:
        return service.ingest_sample(sample_id, actor="api")
    except IngestionError as exc:
        raise _operator_error(exc) from exc
    except (DatabaseError, SQLAlchemyError) as exc:
        raise _database_unavailable(exc) from exc
