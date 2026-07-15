"""Phase 0-2 cross-process-contract ingestion and restart verification."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from uuid import UUID

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from aegishunt import cli
from aegishunt.api.app import create_app
from aegishunt.config import ApplicationSettings, DatabaseSettings, IngestionSettings
from aegishunt.schemas.enums import LifecycleStatus
from aegishunt.storage import Database
from aegishunt.storage.repositories import (
    AuditLogRepository,
    NetworkFlowRepository,
    TelemetrySourceRepository,
)

SAMPLE_ROOT = Path(__file__).parents[2] / "data" / "sample"


def _settings(tmp_path: Path) -> ApplicationSettings:
    return ApplicationSettings(
        database=DatabaseSettings(
            url=f"sqlite:///{tmp_path / 'integration.sqlite3'}",
            busy_timeout_ms=10_000,
        ),
        ingestion=IngestionSettings(
            storage_root=tmp_path / "raw",
            sample_root=SAMPLE_ROOT,
            max_upload_bytes=2_048,
            chunk_size_bytes=32,
            max_records=20,
        ),
    )


def _assert_completed(
    payload: dict[str, object],
    expected: bytes,
    records: int,
    original_filename: str,
    storage_root: Path,
) -> None:
    assert payload["status"] == "completed"
    assert payload["progress"] == 1.0
    assert payload["original_filename"] == original_filename
    assert payload["records_processed"] == records
    assert payload["checksum"] == hashlib.sha256(expected).hexdigest()
    assert payload["byte_size"] == len(expected)
    assert payload["stored_filename"]
    assert Path(str(payload["stored_filename"])).name == payload["stored_filename"]
    stored_path = (storage_root / str(payload["stored_filename"])).resolve()
    assert stored_path.is_relative_to(storage_root.resolve())
    assert stored_path.read_bytes() == expected
    started_at = datetime.fromisoformat(str(payload["started_at"]).replace("Z", "+00:00"))
    completed_at = datetime.fromisoformat(str(payload["completed_at"]).replace("Z", "+00:00"))
    assert completed_at >= started_at
    assert payload["error"] is None
    UUID(str(payload["job_id"]))


def test_configuration_to_ingestion_persistence_and_application_restart(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    pcap = (SAMPLE_ROOT / "phase2-benign.pcap").read_bytes()
    csv_payload = (SAMPLE_ROOT / "phase2-flows.csv").read_bytes()
    json_payload = b'[{"event":"login"},{"event":"logout"}]'
    jobs: list[dict[str, object]] = []

    with TestClient(create_app(settings)) as client:
        requests = (
            ("/ingestion/pcap", "capture.pcap", pcap, "application/vnd.tcpdump.pcap", 1),
            ("/ingestion/flow-csv", "flows.csv", csv_payload, "text/csv", 2),
            ("/ingestion/json-events", "events.json", json_payload, "application/json", 2),
        )
        for endpoint, filename, payload, content_type, records in requests:
            response = client.post(endpoint, files={"file": (filename, payload, content_type)})
            assert response.status_code == 201
            job = response.json()
            _assert_completed(
                job,
                payload,
                records,
                filename,
                settings.ingestion.storage_root,
            )
            jobs.append(job)

        sample_response = client.post("/ingestion/samples/phase2-benign-pcap")
        assert sample_response.status_code == 201
        sample_job = sample_response.json()
        _assert_completed(
            sample_job,
            pcap,
            1,
            "phase2-benign.pcap",
            settings.ingestion.storage_root,
        )
        jobs.append(sample_job)

        listed = client.get("/ingestion/jobs", params={"limit": 10, "offset": 0})
        assert listed.status_code == 200
        assert listed.json()["total"] == 4
        for job in jobs:
            assert client.get(f"/ingestion/jobs/{job['job_id']}").json() == job

    database = Database(settings.database)
    database.initialize()
    try:
        with database.session() as session:
            source_repository = TelemetrySourceRepository(session)
            for job in jobs:
                source = source_repository.get(UUID(str(job["job_id"])))
                assert source is not None
                assert source.status is LifecycleStatus.COMPLETED
            assert len(AuditLogRepository(session).list()) == 16
            assert NetworkFlowRepository(session).list() == []
    finally:
        database.dispose()

    with TestClient(create_app(settings)) as restarted_client:
        for job in jobs:
            response = restarted_client.get(f"/ingestion/jobs/{job['job_id']}")
            assert response.status_code == 200
            assert response.json() == job


def test_cli_ingests_pcap_csv_json_and_allowlisted_sample(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    config_path = tmp_path / "application.yaml"
    events_path = tmp_path / "events.jsonl"
    config_path.write_text(
        f"""
database:
  url: {settings.database.url}
ingestion:
  storage_root: {settings.ingestion.storage_root}
  sample_root: {SAMPLE_ROOT}
  max_upload_bytes: 2048
  chunk_size_bytes: 32
  max_records: 20
""".strip(),
        encoding="utf-8",
    )
    events_path.write_text('{"event":"one"}\n{"event":"two"}\n', encoding="utf-8")
    runner = CliRunner()
    commands = (
        ["ingest", "pcap", str(SAMPLE_ROOT / "phase2-benign.pcap")],
        ["ingest", "csv", str(SAMPLE_ROOT / "phase2-flows.csv")],
        ["ingest", "json", str(events_path)],
        ["ingest", "sample", "phase2-flow-csv"],
    )

    for command in commands:
        result = runner.invoke(cli.app, [*command, "--config", str(config_path)])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["status"] == "completed"

    database = Database(settings.database)
    database.initialize()
    try:
        with database.session() as session:
            assert len(TelemetrySourceRepository(session).list()) == 4
            assert len(AuditLogRepository(session).list()) == 16
            assert NetworkFlowRepository(session).list() == []
    finally:
        database.dispose()
