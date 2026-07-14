"""Minimal FastAPI application for the Phase 0 foundation."""

from __future__ import annotations

from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel

from aegishunt.config import FoundationSettings
from aegishunt.metadata import APPLICATION_DESCRIPTION, APPLICATION_NAME, __version__


class HealthResponse(BaseModel):
    """Public health payload for the application shell."""

    application: str
    version: str
    status: Literal["ok"]
    environment: str


def create_app(settings: FoundationSettings | None = None) -> FastAPI:
    """Create the Phase 0 API without initializing later-phase services."""

    runtime_settings = settings or FoundationSettings.from_environment()
    application = FastAPI(
        title=APPLICATION_NAME,
        description=APPLICATION_DESCRIPTION,
        version=__version__,
    )

    @application.get("/health", response_model=HealthResponse, tags=["system"])
    def health() -> HealthResponse:
        """Report that the API process and Phase 0 configuration are available."""

        return HealthResponse(
            application=APPLICATION_NAME,
            version=__version__,
            status="ok",
            environment=runtime_settings.environment,
        )

    return application


app = create_app()
