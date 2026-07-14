"""Tests for the Phase 0 FastAPI application."""

from fastapi.testclient import TestClient

from aegishunt.api.app import create_app
from aegishunt.config import FoundationSettings


def test_health_endpoint_returns_structured_status() -> None:
    client = TestClient(create_app(FoundationSettings(environment="test")))

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "application": "AegisHunt",
        "version": "0.1.0",
        "status": "ok",
        "environment": "test",
    }
