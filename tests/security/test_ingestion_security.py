"""Negative and security regression coverage for the Phase 2 file boundary."""

from __future__ import annotations

import logging
import struct
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError

from aegishunt.api.app import create_app
from aegishunt.config import ApplicationSettings, DatabaseSettings, IngestionSettings
from aegishunt.storage import Database
from aegishunt.storage.repositories import TelemetrySourceRepository

SAMPLE_ROOT = Path(__file__).parents[2] / "data" / "sample"


def _settings(tmp_path: Path, *, storage_root: Path | None = None) -> ApplicationSettings:
    return ApplicationSettings(
        database=DatabaseSettings(url=f"sqlite:///{tmp_path / 'security.sqlite3'}"),
        ingestion=IngestionSettings(
            storage_root=storage_root or tmp_path / "raw",
            sample_root=SAMPLE_ROOT,
            max_upload_bytes=512,
            chunk_size_bytes=16,
            max_records=10,
        ),
    )


def _forged_pcap() -> bytes:
    return struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 0xFFFFFFFF, 1) + struct.pack(
        "<IIII", 0, 0, 0xFFFFFFFE, 0xFFFFFFFE
    )


PCAP = (SAMPLE_ROOT / "phase2-benign.pcap").read_bytes()
CASES = (
    pytest.param(
        "/ingestion/pcap", "zero.pcap", b"", "application/octet-stream", True, id="zero-pcap"
    ),
    pytest.param(
        "/ingestion/pcap",
        "invalid.pcap",
        b"invalid",
        "application/octet-stream",
        True,
        id="invalid-magic",
    ),
    pytest.param(
        "/ingestion/pcap",
        "header.pcap",
        PCAP[:8],
        "application/octet-stream",
        True,
        id="truncated-header",
    ),
    pytest.param(
        "/ingestion/pcap",
        "packet.pcap",
        PCAP[:-1],
        "application/octet-stream",
        True,
        id="truncated-record",
    ),
    pytest.param(
        "/ingestion/pcap",
        "forged.pcap",
        _forged_pcap(),
        "application/octet-stream",
        True,
        id="declared-length",
    ),
    pytest.param(
        "/ingestion/flow-csv",
        "syntax.csv",
        b'a,b\n"unterminated',
        "text/csv",
        True,
        id="invalid-csv",
    ),
    pytest.param(
        "/ingestion/flow-csv", "headers.csv", b"a,b\n1,2\n", "text/csv", True, id="missing-headers"
    ),
    pytest.param(
        "/ingestion/flow-csv", "binary.csv", b"\xff\xfe\x00", "text/csv", True, id="binary-csv"
    ),
    pytest.param(
        "/ingestion/json-events",
        "invalid.json",
        b"{broken",
        "application/json",
        True,
        id="invalid-json",
    ),
    pytest.param(
        "/ingestion/json-events",
        "scalar.json",
        b"42",
        "application/json",
        True,
        id="unexpected-json",
    ),
    pytest.param(
        "/ingestion/pcap",
        "capture.txt",
        PCAP,
        "application/octet-stream",
        False,
        id="unsupported-extension",
    ),
    pytest.param(
        "/ingestion/pcap", "capture.pcap", PCAP, "application/json", False, id="content-mismatch"
    ),
    pytest.param(
        "/ingestion/pcap",
        "large.pcap",
        b"X" * 513,
        "application/octet-stream",
        True,
        id="oversized",
    ),
    pytest.param(
        "/ingestion/pcap",
        "../../outside.pcap",
        PCAP,
        "application/octet-stream",
        False,
        id="traversal",
    ),
    pytest.param(
        "/ingestion/pcap",
        "__ABSOLUTE_PATH__",
        PCAP,
        "application/octet-stream",
        False,
        id="absolute-path",
    ),
)


@pytest.mark.parametrize(("endpoint", "filename", "content", "content_type", "has_job"), CASES)
def test_rejected_uploads_fail_closed_without_path_or_error_leakage(
    tmp_path: Path,
    endpoint: str,
    filename: str,
    content: bytes,
    content_type: str,
    has_job: bool,
) -> None:
    settings = _settings(tmp_path)
    traversal_outside = tmp_path.parent / "outside.pcap"
    absolute_outside = tmp_path.parent / "absolute-outside.pcap"
    request_filename = str(absolute_outside) if filename == "__ABSOLUTE_PATH__" else filename

    with TestClient(create_app(settings)) as client:
        response = client.post(
            endpoint,
            files={"file": (request_filename, content, content_type)},
        )
        assert response.status_code == 422
        detail = response.json()["detail"]
        assert bool(detail.get("job_id")) is has_job
        if has_job:
            job = client.get(f"/ingestion/jobs/{detail['job_id']}")
            assert job.status_code == 200
            assert job.json()["status"] == "failed"
            assert job.json()["error"] is not None
        assert not any(
            forbidden in response.text
            for forbidden in (str(tmp_path), "Traceback", "sqlite:///", "SELECT ")
        )

    assert not traversal_outside.exists()
    assert not absolute_outside.exists()
    raw = tmp_path / "raw"
    assert not raw.exists() or list(raw.iterdir()) == []


def test_duplicate_names_and_content_create_jobs_without_overwrite(tmp_path: Path) -> None:
    settings = _settings(tmp_path)

    with TestClient(create_app(settings)) as client:
        responses = [
            client.post(
                "/ingestion/pcap",
                files={"file": (filename, PCAP, "application/octet-stream")},
            )
            for filename in ("same.pcap", "same.pcap", "different.pcap")
        ]

    assert [response.status_code for response in responses] == [201, 201, 201]
    jobs = [response.json() for response in responses]
    assert len({job["job_id"] for job in jobs}) == 3
    assert len({job["stored_filename"] for job in jobs}) == 1
    assert len(list((tmp_path / "raw").iterdir())) == 1


def test_unavailable_storage_persists_safe_failed_job(tmp_path: Path) -> None:
    blocked_root = tmp_path / "blocked"
    blocked_root.write_text("not a directory", encoding="utf-8")
    settings = _settings(tmp_path, storage_root=blocked_root)

    with TestClient(create_app(settings)) as client:
        response = client.post(
            "/ingestion/pcap",
            files={"file": ("capture.pcap", PCAP, "application/octet-stream")},
        )
        assert response.status_code == 422
        detail = response.json()["detail"]
        assert detail["code"] == "file_storage_error"
        failed = client.get(f"/ingestion/jobs/{detail['job_id']}").json()
        assert failed["status"] == "failed"
        assert str(tmp_path) not in response.text


def test_database_failure_is_generic_and_never_commits_a_job(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Capture fail-closed behavior; missing durable traceability is reported separately."""

    settings = _settings(tmp_path)
    database = Database(settings.database)
    original_session = database.session

    @contextmanager
    def failing_session() -> Iterator[None]:
        raise SQLAlchemyError("controlled database failure marker")
        yield

    try:
        with (
            caplog.at_level(logging.ERROR, logger="aegishunt.api.routes.ingestion"),
            TestClient(
                create_app(settings, database), raise_server_exceptions=False
            ) as client,
        ):
            monkeypatch.setattr(database, "session", failing_session)
            response = client.post(
                "/ingestion/pcap",
                files={"file": ("capture.pcap", PCAP, "application/octet-stream")},
            )
            assert response.status_code == 503
            assert response.json()["detail"] == {
                "code": "database_unavailable",
                "message": "database is unavailable; request was not completed",
            }
            assert "controlled database failure marker" not in response.text
            assert str(tmp_path) not in response.text
            monkeypatch.setattr(database, "session", original_session)
            with database.session() as session:
                assert TelemetrySourceRepository(session).list() == []
        assert caplog.messages == ["database operation is unavailable; request was not completed"]
        assert "controlled database failure marker" not in caplog.text
        assert str(tmp_path) not in caplog.text
    finally:
        database.dispose()
