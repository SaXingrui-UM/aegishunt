"""FastAPI application with Phase 1 database lifecycle initialization."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel

from aegishunt.api.routes.ingestion import router as ingestion_router
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
    )
    application.include_router(ingestion_router)

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
