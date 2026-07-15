"""PCAP-to-flow extraction, persistence, replay, and restart integration tests."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest

from aegishunt.config import DatabaseSettings, FlowSettings, IngestionSettings
from aegishunt.flows.errors import PacketParseError
from aegishunt.flows.registry import FEATURE_SCHEMA_VERSION
from aegishunt.flows.service import PcapFlowProcessor
from aegishunt.ingestion.errors import IngestionJobFailedError
from aegishunt.ingestion.service import IngestionService
from aegishunt.schemas.enums import LifecycleStatus, SourceType
from aegishunt.storage import Database
from aegishunt.storage.repositories import NetworkFlowRepository, TelemetrySourceRepository
from tests.fixtures.packets import at, tcp_ipv4_frame, write_pcap

SAMPLE_ROOT = Path(__file__).parents[2] / "data" / "sample"
SOURCE_ID = UUID("22222222-2222-2222-2222-222222222222")


def flow_settings(**overrides: float | int) -> FlowSettings:
    return FlowSettings.model_validate(
        {
            "idle_timeout_seconds": 10.0,
            "active_timeout_seconds": 100.0,
            "max_packets_per_flow": 100,
            "max_active_flows": 100,
            "max_packet_bytes": 2_048,
            **overrides,
        }
    )


def test_processor_builds_one_bidirectional_flow_and_replays_deterministically(
    tmp_path: Path,
) -> None:
    capture = write_pcap(
        tmp_path / "bidirectional.pcap",
        [
            (at(0), tcp_ipv4_frame(flags=0x02)),
            (
                at(0.1),
                tcp_ipv4_frame(
                    source_ip="198.51.100.2",
                    destination_ip="192.0.2.1",
                    source_port=443,
                    destination_port=40_000,
                    flags=0x12,
                ),
            ),
            (at(0.2), tcp_ipv4_frame(flags=0x10)),
        ],
    )
    processor = PcapFlowProcessor(flow_settings(), max_records=10)

    first = processor.process(capture, source_id=SOURCE_ID, capture_session_id="capture-1")
    second = processor.process(capture, source_id=SOURCE_ID, capture_session_id="capture-1")

    assert first == second
    assert (first.captured_packets, first.decoded_packets, first.skipped_packets) == (3, 3, 0)
    assert len(first.flows) == 1
    flow = first.flows[0]
    assert (flow.forward_packet_count, flow.backward_packet_count) == (2, 1)
    assert flow.behavioral_features["completed_handshake_indicator"] == 1


def test_timeout_boundary_segments_capture_and_unsupported_frames_are_skipped(
    tmp_path: Path,
) -> None:
    first = tcp_ipv4_frame()
    capture = write_pcap(tmp_path / "timeout.pcap", [(at(0), first), (at(5), first)])
    result = PcapFlowProcessor(
        flow_settings(idle_timeout_seconds=5.0),
        max_records=10,
    ).process(capture, source_id=SOURCE_ID, capture_session_id="timeout")
    assert len(result.flows) == 2

    non_ip = write_pcap(tmp_path / "non-ip.pcap", [(at(0), b"not-decoded")], link_type=999)
    skipped = PcapFlowProcessor(flow_settings(), max_records=10).process(
        non_ip,
        source_id=SOURCE_ID,
        capture_session_id="unsupported",
    )
    assert skipped.flows == ()
    assert (skipped.captured_packets, skipped.decoded_packets, skipped.skipped_packets) == (1, 0, 1)


def test_structurally_malformed_packet_fails_the_capture(tmp_path: Path) -> None:
    capture = write_pcap(tmp_path / "malformed.pcap", [(at(0), b"short")])
    with pytest.raises(PacketParseError, match="Ethernet"):
        PcapFlowProcessor(flow_settings(), max_records=10).process(
            capture,
            source_id=SOURCE_ID,
            capture_session_id="malformed",
        )


def test_ingestion_persists_flows_atomically_and_survives_restart(tmp_path: Path) -> None:
    database_settings = DatabaseSettings(url=f"sqlite:///{tmp_path / 'phase3.sqlite3'}")
    ingestion_settings = IngestionSettings(
        storage_root=tmp_path / "raw",
        sample_root=SAMPLE_ROOT,
        max_upload_bytes=2_048,
        chunk_size_bytes=16,
        max_records=10,
    )
    database = Database(database_settings)
    database.initialize()
    service = IngestionService(
        database,
        ingestion_settings,
        flow_settings=flow_settings(),
    )
    try:
        job = service.ingest_sample("phase2-benign-pcap", actor="phase3-test")
        assert job.status is LifecycleStatus.COMPLETED
        assert job.format_metadata["flow_count"] == 1
        assert job.format_metadata["feature_schema_version"] == FEATURE_SCHEMA_VERSION
        with database.session() as session:
            flows = NetworkFlowRepository(session).list_by_source(job.job_id)
        assert len(flows) == 1
        assert flows[0].source_id == job.job_id
        assert flows[0].behavioral_features["total_packets"] == 1
    finally:
        database.dispose()

    restarted = Database(database_settings)
    restarted.initialize()
    try:
        with restarted.session() as session:
            persisted_source = TelemetrySourceRepository(session).get(job.job_id)
            persisted_flows = NetworkFlowRepository(session).list_by_source(job.job_id)
        assert persisted_source is not None
        assert persisted_source.status is LifecycleStatus.COMPLETED
        assert persisted_flows == flows
    finally:
        restarted.dispose()


def test_packet_failure_persists_failed_job_without_partial_flows(tmp_path: Path) -> None:
    database = Database(DatabaseSettings(url=f"sqlite:///{tmp_path / 'failure.sqlite3'}"))
    database.initialize()
    service = IngestionService(
        database,
        IngestionSettings(
            storage_root=tmp_path / "raw",
            sample_root=SAMPLE_ROOT,
            max_upload_bytes=2_048,
            chunk_size_bytes=16,
            max_records=10,
        ),
        flow_settings=flow_settings(),
    )
    malformed = write_pcap(tmp_path / "malformed.pcap", [(at(0), b"short")])
    try:
        with pytest.raises(IngestionJobFailedError) as failure:
            service.ingest_path(malformed, source_type=SourceType.PCAP)
        job = service.get_job(failure.value.job_id)
        assert job.status is LifecycleStatus.FAILED
        assert job.error is not None
        assert job.error.code == "telemetry_format_error"
        assert "Ethernet" in job.error.message
        with database.session() as session:
            assert NetworkFlowRepository(session).list_by_source(job.job_id) == []
        assert list((tmp_path / "raw").glob("*.pcap")) == []
    finally:
        database.dispose()


def test_duplicate_capture_jobs_have_equivalent_source_scoped_flows(tmp_path: Path) -> None:
    database = Database(DatabaseSettings(url=f"sqlite:///{tmp_path / 'repeat.sqlite3'}"))
    database.initialize()
    service = IngestionService(
        database,
        IngestionSettings(
            storage_root=tmp_path / "raw",
            sample_root=SAMPLE_ROOT,
            max_upload_bytes=2_048,
            chunk_size_bytes=16,
            max_records=10,
        ),
        flow_settings=flow_settings(),
    )
    try:
        first_job = service.ingest_sample("phase2-benign-pcap")
        second_job = service.ingest_sample("phase2-benign-pcap")
        with database.session() as session:
            first = NetworkFlowRepository(session).list_by_source(first_job.job_id)[0]
            second = NetworkFlowRepository(session).list_by_source(second_job.job_id)[0]
        comparable_fields = (
            "first_seen",
            "last_seen",
            "duration",
            "source_ip",
            "destination_ip",
            "source_port",
            "destination_port",
            "protocol",
            "forward_packet_count",
            "backward_packet_count",
            "forward_bytes",
            "backward_bytes",
            "behavioral_features",
        )
        assert all(getattr(first, field) == getattr(second, field) for field in comparable_fields)
        assert first.flow_id != second.flow_id
        assert first.source_id != second.source_id
    finally:
        database.dispose()
