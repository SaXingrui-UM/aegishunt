"""Runtime source-safety, observability, shutdown, and transaction tests."""

from __future__ import annotations

import threading
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy.exc import IntegrityError

from aegishunt.config import ApplicationSettings, DatabaseSettings, IngestionSettings
from aegishunt.detection.service import DetectionAlertService
from aegishunt.runtime.clock import RuntimeClock
from aegishunt.runtime.config import load_runtime_policy
from aegishunt.runtime.contracts import (
    RuntimeCounters,
    RuntimeJobStatus,
    RuntimeResourceSample,
    RuntimeWorker,
    RuntimeWorkerStatus,
)
from aegishunt.runtime.errors import (
    RuntimePersistenceError,
    RuntimePreflightError,
    RuntimeStateError,
)
from aegishunt.runtime.pipeline import (
    ReplayInterrupted,
    RuntimePipelineRunner,
)
from aegishunt.runtime.preflight import LoadedRuntimePipeline
from aegishunt.runtime.repositories import (
    RuntimeJobRepository,
    RuntimeOutputLedgerRepository,
    RuntimeResourceRepository,
    RuntimeWorkerRepository,
)
from aegishunt.runtime.service import RuntimeJobService
from aegishunt.runtime.worker import RuntimeWorkerProcess
from aegishunt.schemas import TelemetrySource
from aegishunt.schemas.enums import IngestionMode, LifecycleStatus, SourceType
from aegishunt.storage import Database
from aegishunt.storage.repositories import (
    NetworkFlowRepository,
    TelemetrySourceRepository,
)
from tests.fixtures.detection import canonical_flow
from tests.fixtures.runtime import NOW, SOURCE_ID, runtime_job

PROJECT_ROOT = Path(__file__).parents[2]


def _database(tmp_path: Path) -> Database:
    database = Database(
        DatabaseSettings(url=f"sqlite:///{tmp_path / 'runtime-queue.sqlite3'}")
    )
    assert database.initialize() == 5
    with database.session() as session, session.begin():
        TelemetrySourceRepository(session).add(
            TelemetrySource(
                source_id=SOURCE_ID,
                source_type=SourceType.PCAP,
                filename_or_interface="phase-11.pcap",
                ingestion_mode=IngestionMode.IMPORT,
                status=LifecycleStatus.COMPLETED,
            )
        )
    return database


def _worker(worker_id: str = "worker-a") -> RuntimeWorker:
    return RuntimeWorker(
        worker_id=worker_id,
        status=RuntimeWorkerStatus.IDLE,
        started_at=NOW,
        heartbeat_at=NOW,
    )


def test_job_creation_rejects_untrusted_or_unverified_sources_before_artifacts(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path)
    storage_root = tmp_path / "raw"
    storage_root.mkdir()
    settings = ApplicationSettings(
        database=DatabaseSettings(url=f"sqlite:///{tmp_path / 'runtime-queue.sqlite3'}"),
        ingestion=IngestionSettings(storage_root=storage_root),
    )
    service = RuntimeJobService(
        database,
        settings=settings,
        runtime_policy=load_runtime_policy(PROJECT_ROOT / "configs" / "runtime.yaml"),
        project_root=PROJECT_ROOT,
    )
    wrong_type = TelemetrySource(
        source_type=SourceType.FLOW_CSV,
        filename_or_interface="flows.csv",
        ingestion_mode=IngestionMode.IMPORT,
        status=LifecycleStatus.COMPLETED,
        records_processed=1,
        checksum="a" * 64,
        source_metadata={"stored_filename": "flows.csv"},
    )
    escaped = TelemetrySource(
        source_type=SourceType.PCAP,
        filename_or_interface="escape.pcap",
        ingestion_mode=IngestionMode.IMPORT,
        status=LifecycleStatus.COMPLETED,
        records_processed=1,
        checksum="b" * 64,
        source_metadata={"stored_filename": "../escape.pcap"},
    )
    target = storage_root / "target.pcap"
    target.write_bytes(b"not-used")
    link = storage_root / "linked.pcap"
    link.symlink_to(target)
    linked = TelemetrySource(
        source_type=SourceType.PCAP,
        filename_or_interface="linked.pcap",
        ingestion_mode=IngestionMode.IMPORT,
        status=LifecycleStatus.COMPLETED,
        records_processed=1,
        checksum="c" * 64,
        source_metadata={"stored_filename": "linked.pcap"},
    )
    try:
        with pytest.raises(RuntimeStateError, match="does not exist"):
            service.create_replay(UUID(int=999_999))
        with pytest.raises(RuntimePreflightError, match="completed checksummed"):
            service.create_replay(SOURCE_ID)
        with database.session() as session, session.begin():
            TelemetrySourceRepository(session).add(wrong_type)
            TelemetrySourceRepository(session).add(escaped)
            TelemetrySourceRepository(session).add(linked)
        with pytest.raises(RuntimePreflightError, match="only a stored PCAP"):
            service.create_replay(wrong_type.source_id)
        with pytest.raises(RuntimePreflightError, match="unsafe logical filename"):
            service.create_replay(escaped.source_id)
        with pytest.raises(RuntimePreflightError, match="regular stored file"):
            service.create_replay(linked.source_id)
        with database.session() as session:
            assert RuntimeJobRepository(session).get_by_source(wrong_type.source_id) is None
            assert RuntimeJobRepository(session).get_by_source(escaped.source_id) is None
            assert RuntimeJobRepository(session).get_by_source(linked.source_id) is None
    finally:
        database.dispose()

def test_resource_samples_are_bounded_and_unavailable_is_retained_as_null(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path)
    try:
        with database.session() as session, session.begin():
            RuntimeWorkerRepository(session).upsert(_worker())
            RuntimeWorkerRepository(session).upsert(_worker("worker-b"))
            repository = RuntimeResourceRepository(session)
            for index in range(4):
                repository.add_and_prune(
                    RuntimeResourceSample(
                        worker_id="worker-a",
                        sampled_at=NOW + timedelta(seconds=index),
                        process_cpu_percent=float(index),
                        process_rss_bytes=index,
                        system_memory_percent=float(index),
                        thread_count=1,
                        sampler_available=True,
                        monitoring_status="available",
                    ),
                    retain=2,
                )
            unavailable = repository.add_and_prune(
                RuntimeResourceSample(
                    worker_id="worker-b",
                    sampled_at=NOW,
                    sampler_available=False,
                    monitoring_status="unavailable",
                    error_code="resource_sampler_unavailable",
                ),
                retain=2,
            )
            assert unavailable.process_cpu_percent is None

        with database.session() as session:
            latest = RuntimeResourceRepository(session).latest()
        assert {sample.worker_id for sample in latest} == {"worker-a", "worker-b"}
        assert next(
            sample for sample in latest if sample.worker_id == "worker-a"
        ).process_cpu_percent == 3.0
    finally:
        database.dispose()


def test_worker_shutdown_moves_job_to_recovery_pending_without_auto_requeue(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    database = _database(tmp_path)
    job = runtime_job()
    try:
        with database.session() as session, session.begin():
            RuntimeJobRepository(session).add(job, actor="operator")

        def interrupt(self: RuntimePipelineRunner, claimed: object) -> RuntimeCounters:
            del self, claimed
            raise ReplayInterrupted("worker shutdown requested")

        monkeypatch.setattr(RuntimePipelineRunner, "run", interrupt)
        settings = ApplicationSettings(
            database=DatabaseSettings(
                url=f"sqlite:///{tmp_path / 'runtime-queue.sqlite3'}"
            )
        )
        worker = RuntimeWorkerProcess(
            database,
            settings=settings,
            runtime_policy=load_runtime_policy(PROJECT_ROOT / "configs" / "runtime.yaml"),
            project_root=PROJECT_ROOT,
            worker_id="shutdown-worker",
            clock=RuntimeClock(now=lambda: NOW, monotonic=lambda: 0.0),
        )
        assert worker.run_one_and_stop() is True

        with database.session() as session:
            interrupted = RuntimeJobRepository(session).get(job.job_id)
        assert interrupted is not None
        assert interrupted.status is RuntimeJobStatus.RECOVERY_PENDING
        assert interrupted.claimed_by is None
        assert interrupted.failure_code == "interrupted"

        with database.session() as session, session.begin():
            recovered = RuntimeJobRepository(session).recover(
                job.job_id,
                actor="operator",
                now=NOW + timedelta(seconds=1),
            )
        assert recovered.status is RuntimeJobStatus.QUEUED
        assert recovered.recovery_count == 1
    finally:
        database.dispose()


def test_runtime_output_batch_rolls_back_flow_ledger_and_progress_together(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    database = _database(tmp_path)
    job = runtime_job()
    policy = load_runtime_policy(PROJECT_ROOT / "configs" / "runtime.yaml")
    try:
        with database.session() as session, session.begin():
            RuntimeWorkerRepository(session).upsert(_worker())
            repository = RuntimeJobRepository(session)
            repository.add(job, actor="operator")
            claimed = repository.claim_next(
                worker_id="worker-a",
                now=NOW,
                lease_seconds=30,
                actor="worker-a",
            )
            assert claimed is not None
            repository.start_attempt(
                job.job_id,
                worker_id="worker-a",
                now=NOW,
                actor="worker-a",
            )
            running = repository.mark_running(
                job.job_id,
                worker_id="worker-a",
                now=NOW,
                actor="worker-a",
            )

        def fail_detection(self: DetectionAlertService, *args: object, **kwargs: object) -> None:
            del self, args, kwargs
            raise IntegrityError("forced detection failure", {}, RuntimeError("forced"))

        monkeypatch.setattr(DetectionAlertService, "evaluate_flow", fail_detection)
        monkeypatch.setattr(
            LoadedRuntimePipeline,
            "scorer",
            lambda self, *, scored_at: object(),
        )
        loaded = LoadedRuntimePipeline(
            source_path=tmp_path / "unused.pcap",
            snapshot=job.snapshot,
            supervised_model=None,  # type: ignore[arg-type]
            anomaly_model=None,  # type: ignore[arg-type]
            fusion_policy=None,  # type: ignore[arg-type]
            fusion_policy_checksum="0" * 64,
            risk_policy=None,  # type: ignore[arg-type]
            explanation_artifact=None,  # type: ignore[arg-type]
            correlation_policy=None,  # type: ignore[arg-type]
        )
        runner = RuntimePipelineRunner(
            database,
            settings=ApplicationSettings(
                database=DatabaseSettings(
                    url=f"sqlite:///{tmp_path / 'runtime-queue.sqlite3'}"
                )
            ),
            runtime_policy=policy,
            project_root=PROJECT_ROOT,
            worker_id="worker-a",
            stop_event=threading.Event(),
        )
        flow = canonical_flow().model_copy(
            update={
                "source_id": SOURCE_ID,
                "capture_session_id": job.snapshot.capture_session_id,
            }
        )
        with pytest.raises(
            RuntimePersistenceError,
            match="runtime output batch rolled back",
        ):
            runner._persist_batch(  # noqa: SLF001 - transaction regression boundary
                running,
                loaded,
                (flow,),
                RuntimeCounters(captured_packets=1, decoded_packets=1),
                progress=0.5,
            )

        with database.session() as session:
            assert NetworkFlowRepository(session).get(flow.flow_id) is None
            assert RuntimeOutputLedgerRepository(session).list_for_job(job.job_id) == ()
            unchanged = RuntimeJobRepository(session).get(job.job_id)
        assert unchanged is not None
        assert unchanged.progress == 0.0
        assert unchanged.counters == RuntimeCounters()
    finally:
        database.dispose()
