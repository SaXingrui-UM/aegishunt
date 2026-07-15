"""Lightweight SQLite concurrency and restart persistence verification."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from aegishunt.config import DatabaseSettings, IngestionSettings
from aegishunt.ingestion.service import IngestionService
from aegishunt.schemas.enums import LifecycleStatus
from aegishunt.storage import Database
from aegishunt.storage.repositories import AuditLogRepository

SAMPLE_ROOT = Path(__file__).parents[2] / "data" / "sample"


def test_five_concurrent_sample_jobs_survive_database_restart(tmp_path: Path) -> None:
    database_path = tmp_path / "concurrent.sqlite3"
    database_settings = DatabaseSettings(
        url=f"sqlite:///{database_path}",
        busy_timeout_ms=10_000,
    )
    ingestion_settings = IngestionSettings(
        storage_root=tmp_path / "raw",
        sample_root=SAMPLE_ROOT,
        max_upload_bytes=1_024,
        chunk_size_bytes=16,
        max_records=10,
    )
    database = Database(database_settings)
    database.initialize()
    service = IngestionService(database, ingestion_settings)
    try:
        with ThreadPoolExecutor(max_workers=5) as executor:
            jobs = list(
                executor.map(
                    lambda index: service.ingest_sample(
                        "phase2-benign-pcap",
                        actor=f"worker-{index}",
                    ),
                    range(5),
                )
            )
        assert len({job.job_id for job in jobs}) == 5
        assert all(job.status is LifecycleStatus.COMPLETED for job in jobs)
        assert len(list((tmp_path / "raw").iterdir())) == 1
        with database.session() as session:
            assert len(AuditLogRepository(session).list()) == 20
    finally:
        database.dispose()

    restarted_database = Database(database_settings)
    restarted_database.initialize()
    try:
        restarted = IngestionService(restarted_database, ingestion_settings)
        page = restarted.list_jobs(limit=10, offset=0)
        assert page.total == 5
        assert all(job.status is LifecycleStatus.COMPLETED for job in page.items)
    finally:
        restarted_database.dispose()
