"""Typed FastAPI dependencies for runtime-owned services."""

from fastapi import Request

from aegishunt.config import ApplicationSettings
from aegishunt.ingestion.service import IngestionService
from aegishunt.storage import Database


def get_database(request: Request) -> Database:
    """Return the database initialized by the application lifespan."""

    database: Database = request.app.state.database
    return database


def get_settings(request: Request) -> ApplicationSettings:
    """Return validated runtime settings without re-reading the environment."""

    settings: ApplicationSettings = request.app.state.settings
    return settings


def get_ingestion_service(request: Request) -> IngestionService:
    """Build a request-scoped service over application-owned resources."""

    return IngestionService(
        get_database(request),
        get_settings(request).ingestion,
    )
