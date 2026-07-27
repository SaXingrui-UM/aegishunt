"""No-root, target-free API-to-flow persistence and restart verification."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

from fastapi.testclient import TestClient

from aegishunt.api.app import create_app
from aegishunt.config import (
    ApplicationSettings,
    DatabaseSettings,
    FlowSettings,
    IngestionSettings,
)
from aegishunt.storage import Database
from aegishunt.storage.repositories import NetworkFlowRepository

SAMPLE_ROOT = Path(__file__).parents[2] / "data" / "sample"


def test_api_pcap_to_flow_survives_application_restart(tmp_path: Path) -> None:
    settings = ApplicationSettings(
        database=DatabaseSettings(url=f"sqlite:///{tmp_path / 'e2e.sqlite3'}"),
        ingestion=IngestionSettings(
            storage_root=tmp_path / "raw",
            sample_root=SAMPLE_ROOT,
            max_upload_bytes=2_048,
            chunk_size_bytes=16,
            max_records=10,
        ),
        flows=FlowSettings(
            idle_timeout_seconds=10.0,
            active_timeout_seconds=100.0,
            max_packets_per_flow=100,
            max_active_flows=100,
            max_packet_bytes=2_048,
        ),
    )
    payload = (SAMPLE_ROOT / "phase2-benign.pcap").read_bytes()

    with TestClient(create_app(settings)) as client:
        response = client.post(
            "/ingestion/pcap",
            files={"file": ("phase3.pcap", payload, "application/vnd.tcpdump.pcap")},
            data={"actor": "phase3-test", "reason": "flow regression", "confirm": "true"},
        )
        assert response.status_code == 201
        job = response.json()
        assert job["status"] == "completed"
        assert job["format_metadata"]["flow_count"] == 1
        assert job["format_metadata"]["decoded_packet_count"] == 1

    source_id = UUID(job["job_id"])
    database = Database(settings.database)
    database.initialize()
    try:
        with database.session() as session:
            before_restart = NetworkFlowRepository(session).list_by_source(source_id)
        assert len(before_restart) == 1
        assert before_restart[0].behavioral_features["total_packets"] == 1
    finally:
        database.dispose()

    with TestClient(create_app(settings)) as restarted_client:
        fetched = restarted_client.get(f"/ingestion/jobs/{source_id}")
        assert fetched.status_code == 200
        assert fetched.json() == job

    restarted_database = Database(settings.database)
    restarted_database.initialize()
    try:
        with restarted_database.session() as session:
            after_restart = NetworkFlowRepository(session).list_by_source(source_id)
        assert after_restart == before_restart
    finally:
        restarted_database.dispose()
