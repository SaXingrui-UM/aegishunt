"""Telemetry upload, sample, and durable ingestion-job endpoints."""

from __future__ import annotations

import logging
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.exc import SQLAlchemyError

from aegishunt.api.contracts import (
    RuntimeReplayRequest,
    SampleIngestRequest,
    TelemetrySourcePage,
)
from aegishunt.api.dependencies import (
    PaginationDependency,
    get_database,
    get_ingestion_service,
    get_runtime_service,
    get_settings,
)
from aegishunt.api.errors import ApiError, not_found
from aegishunt.config import ApplicationSettings
from aegishunt.errors import DatabaseError
from aegishunt.ingestion.errors import (
    IngestionError,
    IngestionJobFailedError,
    IngestionJobNotFoundError,
)
from aegishunt.ingestion.schemas import IngestionJob, IngestionJobPage, SampleDescriptor
from aegishunt.ingestion.service import IngestionService
from aegishunt.runtime.contracts import RuntimeJob
from aegishunt.runtime.service import RuntimeJobService
from aegishunt.schemas import TelemetrySource
from aegishunt.schemas.enums import SourceType
from aegishunt.storage import Database
from aegishunt.storage.repositories import TelemetrySourceRepository

router = APIRouter(prefix="/ingestion", tags=["ingestion"])
logger = logging.getLogger(__name__)
ServiceDependency = Annotated[IngestionService, Depends(get_ingestion_service)]
UploadDependency = Annotated[UploadFile, File(description="Bounded telemetry upload")]
DatabaseDependency = Annotated[Database, Depends(get_database)]
RuntimeDependency = Annotated[RuntimeJobService, Depends(get_runtime_service)]
SettingsDependency = Annotated[ApplicationSettings, Depends(get_settings)]
ActorForm = Annotated[str, Form(min_length=1, max_length=128)]
ReasonForm = Annotated[str, Form(min_length=1, max_length=1_000)]
ConfirmForm = Annotated[bool, Form()]


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
    maximum_bytes: int,
    *,
    actor: str,
    reason: str,
    confirm: bool,
) -> IngestionJob:
    if not confirm:
        raise ApiError(
            "explicit upload confirmation is required",
            code="confirmation_required",
            status_code=400,
        )
    upload_size = file.size
    if upload_size is None:
        try:
            position = file.file.tell()
            file.file.seek(0, 2)
            upload_size = file.file.tell()
            file.file.seek(position)
        except (OSError, ValueError) as exc:
            raise ApiError(
                "upload size could not be verified",
                code="upload_size_unavailable",
                status_code=422,
            ) from exc
    if upload_size > maximum_bytes:
        raise ApiError(
            "upload exceeds the configured limit",
            code="upload_too_large",
            status_code=413,
        )
    try:
        return service.ingest_stream(
            file.file,
            filename=file.filename or "",
            content_type=file.content_type,
            source_type=source_type,
            actor=actor,
            extra_metadata={"mutation_reason": reason},
        )
    except IngestionError as exc:
        raise _operator_error(exc) from exc
    except (DatabaseError, SQLAlchemyError) as exc:
        raise _database_unavailable(exc) from exc


@router.post("/pcap", response_model=IngestionJob, status_code=status.HTTP_201_CREATED)
def upload_pcap(
    file: UploadDependency,
    service: ServiceDependency,
    settings: SettingsDependency,
    actor: ActorForm,
    reason: ReasonForm,
    confirm: ConfirmForm,
) -> IngestionJob:
    """Validate and safely store a PCAP container without decoding packets."""

    return _ingest_upload(
        file,
        service,
        SourceType.PCAP,
        settings.web.maximum_pcap_upload_bytes,
        actor=actor,
        reason=reason,
        confirm=confirm,
    )


@router.post("/csv", response_model=IngestionJob, status_code=status.HTTP_201_CREATED)
@router.post(
    "/flow-csv",
    response_model=IngestionJob,
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False,
)
def upload_flow_csv(
    file: UploadDependency,
    service: ServiceDependency,
    settings: SettingsDependency,
    actor: ActorForm,
    reason: ReasonForm,
    confirm: ConfirmForm,
) -> IngestionJob:
    """Validate and safely store a canonical flow CSV."""

    return _ingest_upload(
        file,
        service,
        SourceType.FLOW_CSV,
        settings.web.maximum_csv_upload_bytes,
        actor=actor,
        reason=reason,
        confirm=confirm,
    )


@router.post("/json", response_model=IngestionJob, status_code=status.HTTP_201_CREATED)
@router.post(
    "/json-events",
    response_model=IngestionJob,
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False,
)
def upload_json_events(
    file: UploadDependency,
    service: ServiceDependency,
    settings: SettingsDependency,
    actor: ActorForm,
    reason: ReasonForm,
    confirm: ConfirmForm,
) -> IngestionJob:
    """Validate and safely store structured JSON events."""

    return _ingest_upload(
        file,
        service,
        SourceType.JSON_EVENT,
        settings.web.maximum_json_upload_bytes,
        actor=actor,
        reason=reason,
        confirm=confirm,
    )


@router.get("/jobs", response_model=IngestionJobPage)
def list_jobs(
    service: ServiceDependency,
    pagination: PaginationDependency,
) -> IngestionJobPage:
    """List durable ingestion jobs with bounded pagination."""

    try:
        return service.list_jobs(limit=pagination.limit, offset=pagination.offset)
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
    include_in_schema=False,
)
def ingest_sample(sample_id: str, service: ServiceDependency) -> IngestionJob:
    """Validate and ingest one allowlisted, checksum-verified sample."""

    try:
        return service.ingest_sample(sample_id, actor="api")
    except IngestionError as exc:
        raise _operator_error(exc) from exc
    except (DatabaseError, SQLAlchemyError) as exc:
        raise _database_unavailable(exc) from exc


@router.post(
    "/sample",
    response_model=IngestionJob,
    status_code=status.HTTP_201_CREATED,
    operation_id="ingest_controlled_sample",
)
def ingest_sample_request(
    payload: SampleIngestRequest,
    service: ServiceDependency,
) -> IngestionJob:
    """Ingest one allowlisted packaged sample after explicit confirmation."""

    try:
        return service.ingest_sample(payload.sample_id, actor=payload.actor)
    except IngestionError as exc:
        raise _operator_error(exc) from exc


@router.get(
    "/sources",
    response_model=TelemetrySourcePage,
    operation_id="list_telemetry_sources",
)
def list_sources(
    database: DatabaseDependency,
    pagination: PaginationDependency,
) -> TelemetrySourcePage:
    """List bounded telemetry provenance records."""

    with database.session() as session:
        items, total = TelemetrySourceRepository(session).list_page(
            limit=pagination.limit,
            offset=pagination.offset,
        )
    return TelemetrySourcePage(
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
    "/sources/{source_id}",
    response_model=TelemetrySource,
    operation_id="get_telemetry_source",
)
def get_source(source_id: UUID, database: DatabaseDependency) -> TelemetrySource:
    """Return one telemetry source without exposing its absolute storage path."""

    with database.session() as session:
        source = TelemetrySourceRepository(session).get(source_id)
    if source is None:
        not_found("telemetry source")
    return source


@router.post(
    "/replay",
    response_model=RuntimeJob,
    status_code=status.HTTP_201_CREATED,
    operation_id="create_ingestion_replay",
)
def create_replay(
    payload: RuntimeReplayRequest,
    service: RuntimeDependency,
) -> RuntimeJob:
    """Create a pinned replay job from a source ID; worker execution remains explicit."""

    if payload.run_now:
        raise ApiError(
            "run_now is not enabled; trigger a bounded worker action separately",
            code="run_now_unavailable",
            status_code=409,
        )
    return service.create_replay(
        payload.source_id,
        speed=payload.speed,
        actor=payload.actor,
    )
