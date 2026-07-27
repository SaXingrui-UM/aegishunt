"""Typed FastAPI dependencies for runtime-owned services."""

from pathlib import Path
from typing import Annotated

from fastapi import Depends, Query, Request

from aegishunt.api.contracts import Pagination
from aegishunt.api.errors import ApiError
from aegishunt.config import ApplicationSettings
from aegishunt.ingestion.service import IngestionService
from aegishunt.runtime.config import load_runtime_policy
from aegishunt.runtime.service import RuntimeJobService
from aegishunt.storage import Database


def get_database(request: Request) -> Database:
    """Return the database initialized by the application lifespan."""

    database: Database = request.app.state.database
    return database


def get_settings(request: Request) -> ApplicationSettings:
    """Return validated runtime settings without re-reading the environment."""

    settings: ApplicationSettings = request.app.state.settings
    return settings


def get_pagination(
    request: Request,
    limit: Annotated[int | None, Query(ge=1, le=100)] = None,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Pagination:
    """Resolve one bounded page using the application WebSettings contract."""

    settings = get_settings(request).web
    effective_limit = settings.default_page_size if limit is None else limit
    if effective_limit > settings.maximum_page_size:
        raise ApiError(
            "page limit exceeds the configured maximum",
            code="page_limit_exceeded",
            status_code=422,
            details={"maximum_page_size": settings.maximum_page_size},
        )
    return Pagination(limit=effective_limit, offset=offset)


PaginationDependency = Annotated[Pagination, Depends(get_pagination)]


def get_ingestion_service(request: Request) -> IngestionService:
    """Build a request-scoped service over application-owned resources."""

    settings = get_settings(request)
    ingestion_settings = settings.ingestion.model_copy(
        update={"chunk_size_bytes": settings.web.upload_chunk_size_bytes}
    )
    return IngestionService(
        get_database(request),
        ingestion_settings,
        flow_settings=settings.flows,
    )


def get_runtime_service(request: Request) -> RuntimeJobService:
    """Build the Phase 11 service with its checksummed runtime policy."""

    settings = get_settings(request)
    return RuntimeJobService(
        get_database(request),
        settings=settings,
        runtime_policy=load_runtime_policy(settings.runtime.policy_path),
        project_root=Path.cwd(),
    )
