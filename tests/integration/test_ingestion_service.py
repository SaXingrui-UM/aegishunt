"""Integration tests for durable ingestion jobs, audit, and failure handling."""

from pathlib import Path

import pytest

from aegishunt.config import DatabaseSettings, IngestionSettings
from aegishunt.ingestion.errors import IngestionJobFailedError
from aegishunt.ingestion.service import IngestionService
from aegishunt.schemas.enums import LifecycleStatus, SourceType
from aegishunt.storage import Database
from aegishunt.storage.repositories import AuditLogRepository, NetworkFlowRepository

SAMPLE_ROOT = Path(__file__).parents[2] / "data" / "sample"


def service_for(tmp_path: Path) -> tuple[Database, IngestionService]:
    database = Database(DatabaseSettings(url=f"sqlite:///{tmp_path / 'ingestion.db'}"))
    database.initialize()
    service = IngestionService(
        database,
        IngestionSettings(
            storage_root=tmp_path / "raw",
            sample_root=SAMPLE_ROOT,
            max_upload_bytes=1_024,
            chunk_size_bytes=16,
            max_records=10,
        ),
    )
    return database, service


def test_sample_pcap_ingestion_persists_completed_job_and_network_flow(
    tmp_path: Path,
) -> None:
    database, service = service_for(tmp_path)
    try:
        job = service.ingest_sample("phase2-benign-pcap", actor="integration-test")

        assert job.status is LifecycleStatus.COMPLETED
        assert job.source_type is SourceType.SAMPLE
        assert job.progress == 1.0
        assert job.records_processed == 1
        assert job.stored_filename is not None
        assert (tmp_path / "raw" / job.stored_filename).is_file()
        assert service.get_job(job.job_id) == job
        page = service.list_jobs(limit=10, offset=0)
        assert page.items == [job]
        assert page.total == 1

        with database.session() as session:
            flows = NetworkFlowRepository(session).list_by_source(job.job_id)
            audit = AuditLogRepository(session).list()
        assert len(flows) == 1
        assert flows[0].behavioral_features["total_packets"] == 1
        assert [event.action for event in audit] == [
            "create",
            "update",
            "update",
            "create",
            "update",
        ]
    finally:
        database.dispose()


def test_malformed_upload_persists_safe_failed_job_and_no_file(tmp_path: Path) -> None:
    database, service = service_for(tmp_path)
    malformed = tmp_path / "malformed.pcap"
    malformed.write_bytes(b"not a pcap")
    try:
        with pytest.raises(IngestionJobFailedError) as failure:
            service.ingest_path(malformed, source_type=SourceType.PCAP)

        job = service.get_job(failure.value.job_id)
        assert job.status is LifecycleStatus.FAILED
        assert job.error is not None
        assert job.error.code == "telemetry_format_error"
        assert job.completed_at is not None
        assert not any(path.name.startswith(".upload-") for path in (tmp_path / "raw").iterdir())
        assert not any(path.suffix == ".pcap" for path in (tmp_path / "raw").iterdir())
    finally:
        database.dispose()
