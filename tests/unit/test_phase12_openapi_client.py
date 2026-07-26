"""Phase 12 OpenAPI and typed frontend-client regression tests."""

from __future__ import annotations

import io
from pathlib import Path

import httpx
from fastapi.testclient import TestClient
from pydantic import ValidationError

from aegishunt.api.app import create_app
from aegishunt.config import ApplicationSettings, DatabaseSettings, WebSettings
from aegishunt.frontend.client import AegisHuntApiClient, ApiClientError
from aegishunt.runtime.contracts import RuntimeWorker
from aegishunt.runtime.repositories import RuntimeWorkerRepository

REQUIRED_ROUTES = {
    "/health",
    "/system/status",
    "/runtime/status",
    "/runtime/jobs",
    "/runtime/jobs/{job_id}",
    "/runtime/workers",
    "/runtime/workers/{worker_id}",
    "/runtime/jobs/{job_id}/pause",
    "/runtime/jobs/{job_id}/resume",
    "/runtime/jobs/{job_id}/recover",
    "/ingestion/pcap",
    "/ingestion/csv",
    "/ingestion/json",
    "/ingestion/replay",
    "/ingestion/jobs",
    "/ingestion/jobs/{job_id}",
    "/ingestion/sources",
    "/ingestion/sources/{source_id}",
    "/ingestion/sample",
    "/flows",
    "/flows/{flow_id}",
    "/flows/summary",
    "/alerts",
    "/alerts/{alert_id}",
    "/alert-groups",
    "/alert-groups/{group_id}",
    "/hypotheses",
    "/hypotheses/{hypothesis_id}",
    "/hypotheses/{hypothesis_id}/create-case",
    "/cases",
    "/cases/{case_id}",
    "/cases/{case_id}/notes",
    "/cases/{case_id}/evidence",
    "/cases/{case_id}/feedback",
    "/cases/{case_id}/close",
    "/cases/{case_id}/report",
    "/feedback",
    "/feedback/{feedback_id}",
    "/feedback/alerts/{alert_id}",
    "/feedback/cases/{case_id}",
    "/feedback/export",
    "/feedback/retraining-candidates",
    "/models",
    "/models/{model_id}",
    "/models/active",
    "/models/{model_id}/importance",
    "/models/train",
    "/models/{model_id}/activate",
    "/evaluation",
    "/evaluation/latest",
    "/evaluation/{run_id}",
    "/demo/status",
    "/demo/sample",
}


def test_openapi_has_unique_documented_phase12_operations(tmp_path: Path) -> None:
    settings = ApplicationSettings(
        database=DatabaseSettings(url=f"sqlite:///{tmp_path / 'openapi.db'}")
    )
    with TestClient(create_app(settings)) as client:
        assert client.get("/docs").status_code == 200
        assert client.get("/redoc").status_code == 200
        schema = client.get("/openapi.json").json()
    assert set(schema["paths"]) >= REQUIRED_ROUTES
    operation_ids = [
        operation["operationId"]
        for path in schema["paths"].values()
        for operation in path.values()
        if isinstance(operation, dict) and "operationId" in operation
    ]
    assert len(operation_ids) == len(set(operation_ids))
    assert all(
        operation.get("responses")
        for path in schema["paths"].values()
        for operation in path.values()
        if isinstance(operation, dict)
    )


def test_pagination_and_request_identity_use_web_configuration(tmp_path: Path) -> None:
    settings = ApplicationSettings(
        database=DatabaseSettings(url=f"sqlite:///{tmp_path / 'pagination.db'}"),
        web=WebSettings(
            default_page_size=7,
            maximum_page_size=10,
            maximum_table_rows=7,
            request_id_header="X-Phase12-Request-ID",
        ),
    )
    with TestClient(create_app(settings)) as client:
        default_page = client.get(
            "/flows",
            headers={"X-Phase12-Request-ID": "phase12-request"},
        )
        rejected = client.get("/flows", params={"limit": 11})
    assert default_page.status_code == 200
    assert default_page.headers["X-Phase12-Request-ID"] == "phase12-request"
    assert default_page.json()["limit"] == 7
    assert default_page.json()["has_more"] is False
    assert rejected.status_code == 422
    assert rejected.json()["error_code"] == "page_limit_exceeded"
    assert rejected.json()["details"] == {"maximum_page_size": 10}


def test_runtime_worker_page_reports_exact_total_beyond_one_hundred(
    tmp_path: Path,
) -> None:
    settings = ApplicationSettings(
        database=DatabaseSettings(url=f"sqlite:///{tmp_path / 'workers.db'}"),
        web=WebSettings(
            default_page_size=10,
            maximum_page_size=10,
            maximum_table_rows=10,
        ),
    )
    app = create_app(settings)
    with TestClient(app) as client:
        with app.state.database.session() as session:
            repository = RuntimeWorkerRepository(session)
            for index in range(101):
                repository.upsert(RuntimeWorker(worker_id=f"worker-{index:03d}"))
            session.commit()

        response = client.get("/runtime/workers", params={"offset": 100})

    assert response.status_code == 200
    assert response.json()["total"] == 101
    assert [item["worker_id"] for item in response.json()["items"]] == ["worker-100"]
    assert response.json()["has_more"] is False


def test_web_configuration_rejects_unsafe_or_incoherent_values() -> None:
    invalid_values = (
        {"api_host": "0.0.0.0"},
        {"api_base_url": "http://user:password@127.0.0.1:8000"},
        {"frontend_origin": "https://example.test"},
        {"frontend_origin": "http://127.0.0.1:8501/not-an-origin"},
        {"default_page_size": 20, "maximum_page_size": 10},
        {"auto_refresh_seconds": 5, "minimum_refresh_seconds": 10},
        {"safe_download_types": ("arbitrary_file",)},
        {"demo_sample_ids": ()},
    )
    for update in invalid_values:
        try:
            WebSettings.model_validate(update)
        except ValidationError:
            pass
        else:
            raise AssertionError(f"unsafe web configuration was accepted: {update}")


def test_disabled_sample_mode_is_read_only_and_fail_closed(tmp_path: Path) -> None:
    settings = ApplicationSettings(
        database=DatabaseSettings(url=f"sqlite:///{tmp_path / 'demo-disabled.db'}"),
        web=WebSettings(sample_mode_enabled=False),
    )
    with TestClient(create_app(settings)) as client:
        status = client.get("/demo/status")
        run = client.post(
            "/demo/sample",
            json={
                "actor": "phase12-test",
                "reason": "verify disabled sample mode",
                "confirm": True,
                "sample_id": "phase12-demo-pcap",
                "create_case": False,
            },
        )
    assert status.status_code == 200
    assert status.json()["available"] is False
    assert status.json()["sample_ids"] == []
    assert run.status_code == 409
    assert run.json()["error_code"] == "demo_mode_disabled"


def test_typed_client_parses_success_and_sanitized_failure() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.url.path == "/demo/status":
            return httpx.Response(
                200,
                json={
                    "available": True,
                    "sample_ids": ["phase2-benign-pcap"],
                    "previous_run": None,
                    "limitations": ["controlled evidence only"],
                },
            )
        if request.url.path == "/flows":
            return httpx.Response(
                200,
                json={
                    "items": [],
                    "total": 0,
                    "limit": 50,
                    "offset": 0,
                    "next_offset": None,
                },
            )
        return httpx.Response(
            503,
            json={
                "error_code": "database_unavailable",
                "message": "database is unavailable",
                "request_id": "request-123",
                "details": None,
                "retryable": True,
                "status_code": 503,
            },
        )

    with AegisHuntApiClient(
        "http://127.0.0.1:8000",
        transport=httpx.MockTransport(handler),
    ) as client:
        status = client.demo_status()
        assert status.available
        assert client.flows(protocol="tcp").total == 0
        try:
            client.system_status()
        except ApiClientError as error:
            assert error.error_code == "database_unavailable"
            assert error.request_id == "request-123"
            assert error.retryable
        else:
            raise AssertionError("expected typed API failure")
    assert calls[1].url.params["protocol"] == "tcp"


def test_client_rejects_non_allowlisted_actions_without_http_request() -> None:
    with AegisHuntApiClient(
        "http://127.0.0.1:8000",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(500, request=request)
        ),
    ) as client:
        for operation in (
            lambda: client.runtime_action(
                "job",
                "shell",
                actor="analyst",
                reason="not allowed",
            ),
            lambda: client.upload(
                "pickle",
                filename="model.pkl",
                stream=io.BytesIO(b"unsafe"),
                content_type="application/octet-stream",
                actor="analyst",
                reason="not allowed",
            ),
            lambda: client.add_feedback(
                "flows",
                "id",
                verdict="true_positive",
                confidence=1.0,
                notes="",
                actor="analyst",
                reason="not allowed",
            ),
        ):
            try:
                operation()
            except ValueError:
                pass
            else:
                raise AssertionError("non-allowlisted client operation was accepted")
