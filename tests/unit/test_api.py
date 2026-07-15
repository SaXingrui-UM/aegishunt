"""Tests for FastAPI startup against an empty Phase 1 database."""

from pathlib import Path

from fastapi.testclient import TestClient

from aegishunt.api.app import create_app
from aegishunt.config import ApplicationSection, ApplicationSettings, DatabaseSettings


def test_health_endpoint_initializes_empty_database(tmp_path: Path) -> None:
    database_path = tmp_path / "api.db"
    settings = ApplicationSettings(
        application=ApplicationSection(environment="test"),
        database=DatabaseSettings(url=f"sqlite:///{database_path}"),
    )

    with TestClient(create_app(settings)) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "application": "AegisHunt",
        "version": "0.1.0",
        "status": "ok",
        "environment": "test",
        "database_status": "ready",
        "schema_version": 1,
    }
    assert database_path.is_file()
