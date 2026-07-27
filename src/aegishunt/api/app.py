"""FastAPI application with Phase 1 database lifecycle initialization."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from aegishunt.api.contracts import ErrorResponse
from aegishunt.api.errors import install_error_handlers
from aegishunt.api.middleware import install_request_id_middleware
from aegishunt.api.routes.alerts import detections_router
from aegishunt.api.routes.alerts import router as alerts_router
from aegishunt.api.routes.cases import router as cases_router
from aegishunt.api.routes.demo import router as demo_router
from aegishunt.api.routes.evaluation import router as evaluation_router
from aegishunt.api.routes.flows import router as flows_router
from aegishunt.api.routes.hunts import router as hunts_router
from aegishunt.api.routes.ingestion import router as ingestion_router
from aegishunt.api.routes.models import router as models_router
from aegishunt.api.routes.runtime import router as runtime_router
from aegishunt.config import ApplicationSettings, load_settings
from aegishunt.metadata import APPLICATION_DESCRIPTION, APPLICATION_NAME, __version__
from aegishunt.storage import Database


class HealthResponse(BaseModel):
    """Public health payload for the application foundation."""

    application: str
    version: str
    status: Literal["ok"]
    environment: str
    database_status: Literal["ready"]
    schema_version: int


def create_app(
    settings: ApplicationSettings | None = None,
    database: Database | None = None,
) -> FastAPI:
    """Create the API and initialize an empty or existing database at startup."""

    runtime_settings = settings or load_settings()
    runtime_database = database or Database(runtime_settings.database)
    owns_database = database is None

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        schema_version = runtime_database.initialize()
        application.state.database = runtime_database
        application.state.settings = runtime_settings
        application.state.schema_version = schema_version
        try:
            yield
        finally:
            if owns_database:
                runtime_database.dispose()

    application = FastAPI(
        title=APPLICATION_NAME,
        description=APPLICATION_DESCRIPTION,
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs" if runtime_settings.web.docs_enabled else None,
        redoc_url="/redoc" if runtime_settings.web.docs_enabled else None,
        openapi_url="/openapi.json" if runtime_settings.web.docs_enabled else None,
        responses={
            code: {
                "model": ErrorResponse,
                "description": description,
            }
            for code, description in (
                (400, "Invalid explicit request"),
                (404, "Resource not found"),
                (409, "State or optimistic concurrency conflict"),
                (413, "Bounded upload limit exceeded"),
                (422, "Validation or domain contract rejection"),
                (500, "Sanitized internal failure"),
                (503, "Required local service unavailable"),
            )
        },
    )
    install_request_id_middleware(
        application,
        header_name=runtime_settings.web.request_id_header,
        maximum_length=runtime_settings.web.request_id_max_length,
    )
    install_error_handlers(application)
    if runtime_settings.web.allowed_origins:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=list(runtime_settings.web.allowed_origins),
            allow_credentials=False,
            allow_methods=["GET", "POST", "PATCH"],
            allow_headers=[
                "Content-Type",
                runtime_settings.web.request_id_header,
                runtime_settings.web.actor_header,
            ],
        )
    for router in (
        runtime_router,
        ingestion_router,
        flows_router,
        detections_router,
        alerts_router,
        hunts_router,
        cases_router,
        models_router,
        evaluation_router,
        demo_router,
    ):
        application.include_router(router)

    @application.get("/health", response_model=HealthResponse, tags=["system"])
    def health() -> HealthResponse:
        """Report process health and the initialized schema version."""

        return HealthResponse(
            application=APPLICATION_NAME,
            version=__version__,
            status="ok",
            environment=runtime_settings.environment,
            database_status="ready",
            schema_version=application.state.schema_version,
        )

    return application


app = create_app()
