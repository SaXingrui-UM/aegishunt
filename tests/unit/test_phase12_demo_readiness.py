"""Focused unit coverage for Phase 12 corrective read models."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from aegishunt.api.audit_service import project_case_audit_event
from aegishunt.api.runtime_model_service import EffectiveRuntimeModelService
from aegishunt.api.runtime_observability import RuntimeObservabilityReader
from aegishunt.config import ApplicationSettings, DatabaseSettings
from aegishunt.runtime.contracts import (
    RuntimeJobStatus,
    RuntimeResourceSample,
    RuntimeStage,
    RuntimeWorker,
    RuntimeWorkerStatus,
)
from aegishunt.runtime.job_store import RuntimeJobStore
from aegishunt.runtime.repositories import (
    RuntimeResourceRepository,
    RuntimeWorkerRepository,
)
from aegishunt.schemas.audit import AuditEvent
from aegishunt.schemas.enums import IngestionMode, LifecycleStatus, SourceType
from aegishunt.schemas.telemetry import TelemetrySource
from aegishunt.storage import Database
from aegishunt.storage.repositories import TelemetrySourceRepository
from tests.fixtures.runtime import runtime_job

NOW = datetime(2026, 7, 28, 9, 0, tzinfo=UTC)


def test_effective_model_state_does_not_invent_global_or_runtime_models(
    tmp_path: Path,
) -> None:
    settings = ApplicationSettings(
        database=DatabaseSettings(url=f"sqlite:///{tmp_path / 'effective.sqlite3'}")
    )
    database = Database(settings.database)
    database.initialize()
    try:
        result = EffectiveRuntimeModelService(database, settings).read()
    finally:
        database.dispose()
    assert result.status == "unavailable"
    assert result.global_active_models == []
    assert result.effective_models == []
    assert result.latest_runtime_job_id is None
    assert result.unavailable_reason is not None


def test_runtime_observability_uses_persisted_job_interval_and_resource_sample(
    tmp_path: Path,
) -> None:
    database = Database(
        DatabaseSettings(url=f"sqlite:///{tmp_path / 'observability.sqlite3'}")
    )
    database.initialize()
    started = NOW
    completed = NOW + timedelta(milliseconds=12.4)
    completed_job = runtime_job(created_at=started).model_copy(
        update={
            "status": RuntimeJobStatus.COMPLETED,
            "current_stage": RuntimeStage.COMPLETION,
            "progress": 1.0,
            "started_at": started,
            "updated_at": completed,
            "completed_at": completed,
        }
    )
    with database.session() as session, session.begin():
        TelemetrySourceRepository(session).add(
            TelemetrySource(
                source_id=completed_job.source_id,
                source_type=SourceType.PCAP,
                filename_or_interface=completed_job.snapshot.stored_filename,
                ingestion_mode=IngestionMode.REPLAY,
                status=LifecycleStatus.COMPLETED,
                started_at=started,
                completed_at=completed,
                records_processed=2,
                checksum=completed_job.snapshot.source_checksum,
            )
        )
        RuntimeJobStore(session).add(completed_job, actor="unit-test")
        RuntimeWorkerRepository(session).upsert(
            RuntimeWorker(
                worker_id="worker-observed",
                status=RuntimeWorkerStatus.STOPPED,
                process_identity_summary="pid:4242",
                started_at=started,
                heartbeat_at=completed,
                stopped_at=completed,
            )
        )
        RuntimeResourceRepository(session).add_and_prune(
            RuntimeResourceSample(
                worker_id="worker-observed",
                job_id=completed_job.job_id,
                sampled_at=completed,
                process_cpu_percent=7.5,
                process_rss_bytes=16_384,
                system_memory_percent=25.0,
                thread_count=4,
                sampler_available=True,
                monitoring_status="available",
            ),
            retain=10,
        )
    try:
        latency, resource = RuntimeObservabilityReader(
            database,
            clock=lambda: completed + timedelta(seconds=1),
        ).read()
    finally:
        database.dispose()
    assert latency.status == "available"
    assert latency.p50_ms == 12.4
    assert latency.p95_ms == 12.4
    assert latency.observation_count == 1
    assert latency.runtime_job_id == completed_job.job_id
    assert resource.status == "available"
    assert resource.process_id == 4242
    assert resource.process_cpu_percent == 7.5
    assert resource.process_rss_bytes == 16_384
    assert resource.active_thread_count == 4


def test_audit_projection_is_bounded_and_redacts_sensitive_metadata() -> None:
    event = AuditEvent(
        actor="analyst",
        action="update_case_status",
        object_type="investigation_cases",
        object_id="case-1",
        created_at=NOW,
        details={
            "reason": "reviewed",
            "before": {"status": "open", "api_token": "must-not-leak"},
            "after": {"status": "investigating"},
            "secret": "must-not-leak",
            "source": "case_service",
        },
    )
    projected = project_case_audit_event(event)
    assert projected.reason == "reviewed"
    assert projected.before_summary == {"status": "open"}
    assert projected.after_summary == {"status": "investigating"}
    assert projected.metadata_summary == {"source": "case_service"}
