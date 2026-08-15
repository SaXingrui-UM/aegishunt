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
    RuntimeJob,
    RuntimeJobStatus,
    RuntimeProgressMode,
    RuntimeResourceSample,
    RuntimeWorker,
    RuntimeWorkerStatus,
)
from aegishunt.runtime.environment import ResolvedRuntimeEnvironment
from aegishunt.runtime.errors import (
    RuntimePersistenceError,
    RuntimePreflightError,
    RuntimeStateError,
)
from aegishunt.runtime.pipeline import (
    ReplayInterrupted,
    RuntimePipelineRunner,
    _groups_for_job,
    _hypotheses_for_groups,
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
from aegishunt.schemas import TelemetrySource, ThreatHypothesis
from aegishunt.schemas.enums import IngestionMode, LifecycleStatus, SourceType
from aegishunt.storage import Database
from aegishunt.storage.repositories import (
    AuditLogRepository,
    DetectionResultRepository,
    NetworkFlowRepository,
    SecurityAlertRepository,
    TelemetrySourceRepository,
)
from tests.fixtures.detection import canonical_flow
from tests.fixtures.hunting import group
from tests.fixtures.packets import at, tcp_ipv4_frame, write_pcap
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


def test_runtime_downstream_observations_exclude_unrelated_historical_evidence() -> None:
    job_group = group()
    unrelated_group = job_group.model_copy(
        update={
            "group_id": UUID(int=4_001),
            "alert_ids": [str(UUID(int=9_001)), str(UUID(int=9_002))],
        }
    )
    job_hypothesis = ThreatHypothesis.model_construct(
        hypothesis_id=UUID(int=5_001),
        group_id=job_group.group_id,
    )
    unrelated_hypothesis = ThreatHypothesis.model_construct(
        hypothesis_id=UUID(int=5_002),
        group_id=unrelated_group.group_id,
    )

    scoped_groups = _groups_for_job(
        (unrelated_group, job_group),
        {job_group.alert_ids[0]},
    )
    assert scoped_groups == (job_group,)
    assert _hypotheses_for_groups(
        (unrelated_hypothesis, job_hypothesis),
        {item.group_id for item in scoped_groups},
    ) == (job_hypothesis,)


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
        assert worker.last_claimed_job_id == job.job_id

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


def test_worker_runs_with_environment_resolved_from_pinned_snapshot(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    database = _database(tmp_path)
    job = runtime_job()
    policy = load_runtime_policy(PROJECT_ROOT / "configs/runtime.yaml")
    configured_settings = ApplicationSettings(
        database=DatabaseSettings(
            url=f"sqlite:///{tmp_path / 'runtime-queue.sqlite3'}"
        )
    )
    historical_settings = configured_settings.model_copy(
        update={
            "application": configured_settings.application.model_copy(
                update={"environment": "historical-demo"}
            )
        }
    )
    selected = ResolvedRuntimeEnvironment(
        settings=historical_settings,
        runtime_policy=policy,
        source="runtime_snapshot_demo",
    )
    observed: dict[str, object] = {}

    def resolve(
        settings: ApplicationSettings,
        snapshot: object,
        *,
        project_root: Path,
    ) -> ResolvedRuntimeEnvironment:
        observed.update(
            {
                "base_settings": settings,
                "snapshot": snapshot,
                "project_root": project_root,
            }
        )
        return selected

    class CapturingRunner:
        def __init__(self, database: Database, **kwargs: object) -> None:
            observed["database"] = database
            observed.update(kwargs)

        def run(self, claimed: RuntimeJob) -> RuntimeCounters:
            observed["job"] = claimed
            raise ReplayInterrupted("captured resolved environment")

    monkeypatch.setattr(
        "aegishunt.runtime.worker.resolve_job_execution_environment",
        resolve,
    )
    monkeypatch.setattr(
        "aegishunt.runtime.worker.RuntimePipelineRunner",
        CapturingRunner,
    )
    try:
        with database.session() as session, session.begin():
            RuntimeJobRepository(session).add(job, actor="operator")

        worker = RuntimeWorkerProcess(
            database,
            settings=configured_settings,
            runtime_policy=policy,
            project_root=PROJECT_ROOT,
            worker_id="snapshot-environment-worker",
            clock=RuntimeClock(now=lambda: NOW, monotonic=lambda: 0.0),
        )
        assert worker.run_one_and_stop() is True

        assert observed["settings"] is historical_settings
        assert observed["runtime_policy"] is policy
        assert observed["snapshot"] == job.snapshot
        claimed = observed["job"]
        assert isinstance(claimed, RuntimeJob)
        assert claimed.job_id == job.job_id
        assert claimed.status is RuntimeJobStatus.VALIDATING
    finally:
        database.dispose()


def test_periodic_observation_does_not_advance_durable_progress_for_open_flow(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    database = _database(tmp_path)
    policy = load_runtime_policy(PROJECT_ROOT / "configs" / "runtime.yaml")
    packet_count = policy.policy.worker.progress_update_packet_interval + 1
    source_path = write_pcap(
        tmp_path / "long-open-flow.pcap",
        [
            (
                at(0.0),
                tcp_ipv4_frame(
                    source_ip="192.0.2.10",
                    destination_ip="198.51.100.20",
                    source_port=40_000,
                    destination_port=443,
                    flags=0x10,
                ),
            )
            for _ in range(packet_count)
        ],
    )
    snapshot = runtime_job().snapshot.model_copy(
        update={
            "stored_filename": source_path.name,
            "source_size_bytes": source_path.stat().st_size,
            "verified_packet_count": packet_count,
        }
    )
    job = RuntimeJob(
        source_id=SOURCE_ID,
        replay_speed=policy.policy.replay.maximum_speed,
        snapshot=snapshot,
        progress_mode=RuntimeProgressMode.PACKET_COUNT,
        progress_total=packet_count,
        created_at=NOW,
        updated_at=NOW,
    )
    stop_event = threading.Event()
    try:
        with database.session() as session, session.begin():
            RuntimeWorkerRepository(session).upsert(_worker())
            repository = RuntimeJobRepository(session, AuditLogRepository(session))
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

        loaded = LoadedRuntimePipeline(
            source_path=source_path,
            snapshot=snapshot,
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
            stop_event=stop_event,
            clock=RuntimeClock(
                now=lambda: NOW,
                monotonic=lambda: 0.0,
                sleep=lambda _: None,
            ),
        )
        monkeypatch.setattr(
            runner._preflight,  # noqa: SLF001 - controlled replay boundary
            "verify",
            lambda source, *, expected_snapshot: loaded,
        )
        original_check = runner._control.check  # noqa: SLF001

        def stop_after_periodic_update(
            job_id: UUID,
            counters: RuntimeCounters,
            progress: float,
        ) -> None:
            original_check(job_id, counters, progress)
            if (
                counters.captured_packets
                >= policy.policy.worker.progress_update_packet_interval
            ):
                stop_event.set()

        monkeypatch.setattr(
            runner._control,  # noqa: SLF001 - injected cooperative interruption
            "check",
            stop_after_periodic_update,
        )

        with pytest.raises(ReplayInterrupted, match="shutdown"):
            runner.run(claimed)

        with database.session() as session:
            persisted = RuntimeJobRepository(session).get(job.job_id)
            flows = NetworkFlowRepository(session).list_by_source(SOURCE_ID)
            detections = DetectionResultRepository(session).list()
            alerts = SecurityAlertRepository(session).list()
            ledgers = RuntimeOutputLedgerRepository(session).list_for_job(job.job_id)
        assert persisted is not None
        assert persisted.counters == RuntimeCounters()
        assert persisted.progress_current == 0
        assert persisted.progress == 0.0
        assert persisted.progress_semantics == "durable_committed_evidence"
        assert persisted.observed_counters.captured_packets == (
            policy.policy.worker.progress_update_packet_interval
        )
        assert persisted.observed_counters.decoded_packets == (
            policy.policy.worker.progress_update_packet_interval
        )
        assert persisted.observed_progress_current == (
            policy.policy.worker.progress_update_packet_interval
        )
        assert persisted.observed_progress > 0.0
        assert (
            persisted.observed_progress_semantics
            == "non_durable_live_observation"
        )
        assert flows == []
        assert detections == []
        assert alerts == []
        assert ledgers == ()

        with database.session() as session, session.begin():
            interrupted = RuntimeJobRepository(
                session,
                AuditLogRepository(session),
            ).interrupt(
                job.job_id,
                worker_id="worker-a",
                reason="injected before first durable flow",
                now=NOW + timedelta(seconds=1),
                actor="worker-a",
            )
        with database.session() as session:
            attempts = RuntimeJobRepository(session).list_attempts(job.job_id)
        assert interrupted.status is RuntimeJobStatus.RECOVERY_PENDING
        assert interrupted.progress == 0.0
        assert interrupted.counters == RuntimeCounters()
        assert interrupted.observed_progress == persisted.observed_progress
        assert attempts[0].status.value == "interrupted"
        assert attempts[0].progress == 0.0
        assert attempts[0].observed_progress == persisted.observed_progress
        assert attempts[0].observed_counters.captured_packets == (
            policy.policy.worker.progress_update_packet_interval
        )
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
            repository.update_observed_progress(
                job.job_id,
                worker_id="worker-a",
                counters=RuntimeCounters(captured_packets=1, decoded_packets=1),
                progress=0.5,
                now=NOW,
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
                RuntimeCounters(),
            )

        with database.session() as session:
            assert NetworkFlowRepository(session).get(flow.flow_id) is None
            assert RuntimeOutputLedgerRepository(session).list_for_job(job.job_id) == ()
            unchanged = RuntimeJobRepository(session).get(job.job_id)
        assert unchanged is not None
        assert unchanged.progress == 0.0
        assert unchanged.counters == RuntimeCounters()
        assert unchanged.observed_progress == 0.5
        assert unchanged.observed_counters.captured_packets == 1
    finally:
        database.dispose()
