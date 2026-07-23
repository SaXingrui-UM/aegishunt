"""Offline Phase 11 source-to-hypothesis runtime and restart E2E."""

from __future__ import annotations

import hashlib
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from aegishunt.config import ApplicationSettings
from aegishunt.ingestion.schemas import IngestionJob
from aegishunt.ingestion.service import IngestionService
from aegishunt.runtime.contracts import (
    RuntimeCounters,
    RuntimeJobStatus,
    RuntimeWorker,
    RuntimeWorkerStatus,
)
from aegishunt.runtime.control import RuntimeControlMonitor
from aegishunt.runtime.errors import RuntimePreflightError, RuntimeStateError
from aegishunt.runtime.pipeline import RuntimePipelineRunner
from aegishunt.runtime.preflight import RuntimePreflightVerifier
from aegishunt.runtime.repositories import (
    RuntimeJobRepository,
    RuntimeOutputLedgerRepository,
    RuntimeWorkerRepository,
)
from aegishunt.runtime.service import RuntimeJobService
from aegishunt.runtime.status import RuntimeStatusReader
from aegishunt.runtime.worker import RuntimeWorkerProcess
from aegishunt.schemas import TelemetrySource
from aegishunt.schemas.enums import (
    IngestionMode,
    LifecycleStatus,
    SourceType,
)
from aegishunt.storage import Database
from aegishunt.storage.repositories import (
    AlertGroupRepository,
    AuditLogRepository,
    DetectionResultRepository,
    NetworkFlowRepository,
    SecurityAlertRepository,
    TelemetrySourceRepository,
    ThreatHypothesisRepository,
)
from tests.fixtures.runtime import PROJECT_ROOT, build_verified_runtime_environment

SAMPLE_PCAP = PROJECT_ROOT / "data" / "sample" / "phase2-benign.pcap"


def _ingest(
    database: Database,
    settings: ApplicationSettings,
) -> IngestionJob:
    return IngestionService(
        database,
        settings.ingestion,
        flow_settings=settings.flows,
    ).ingest_path(
        SAMPLE_PCAP,
        source_type=SourceType.PCAP,
        content_type="application/vnd.tcpdump.pcap",
        actor="phase-11-e2e",
    )


def test_phase_11_replay_persists_verified_pipeline_and_survives_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings, runtime_policy = build_verified_runtime_environment(tmp_path)
    database = Database(settings.database)
    assert database.initialize() == 5
    try:
        ingestion = _ingest(database, settings)
        service = RuntimeJobService(
            database,
            settings=settings,
            runtime_policy=runtime_policy,
            project_root=PROJECT_ROOT,
        )
        job = service.create_replay(
            ingestion.job_id,
            speed=runtime_policy.policy.replay.maximum_speed,
            actor="phase-11-e2e",
        )
        assert job.status is RuntimeJobStatus.QUEUED
        assert Path(job.snapshot.stored_filename).name == job.snapshot.stored_filename
        assert len(job.snapshot.artifacts) == 7
        assert job.snapshot.database_schema_version == 5
        with pytest.raises(RuntimeStateError, match="already has"):
            service.create_replay(ingestion.job_id, actor="phase-11-e2e")

        original_control_check = RuntimeControlMonitor.check
        pause_injected = False
        resume_errors: list[BaseException] = []

        def pause_once(
            monitor: RuntimeControlMonitor,
            job_id: UUID,
            counters: RuntimeCounters,
            progress: float,
        ) -> None:
            nonlocal pause_injected
            if pause_injected:
                original_control_check(monitor, job_id, counters, progress)
                return
            pause_injected = True
            service.pause(job.job_id, actor="phase-11-e2e")

            def resume_when_acknowledged() -> None:
                try:
                    deadline = time.monotonic() + 5.0
                    while time.monotonic() < deadline:
                        if service.get(job.job_id).status is RuntimeJobStatus.PAUSED:
                            service.resume(job.job_id, actor="phase-11-e2e")
                            return
                        time.sleep(0.01)
                    raise TimeoutError("runtime worker did not acknowledge pause")
                except BaseException as exc:  # thread evidence is re-raised below
                    resume_errors.append(exc)

            resume_thread = threading.Thread(target=resume_when_acknowledged)
            resume_thread.start()
            original_control_check(monitor, job.job_id, counters, progress)
            resume_thread.join(timeout=6.0)
            if resume_thread.is_alive():
                raise TimeoutError("runtime resume helper did not terminate")
            if resume_errors:
                raise resume_errors[0]

        monkeypatch.setattr(RuntimeControlMonitor, "check", pause_once)
        worker = RuntimeWorkerProcess(
            database,
            settings=settings,
            runtime_policy=runtime_policy,
            project_root=PROJECT_ROOT,
            worker_id="phase-11-worker",
        )
        assert worker.run_one_and_stop() is True
        completed = service.get(job.job_id)
        assert completed.status is RuntimeJobStatus.COMPLETED
        assert completed.progress == 1.0
        assert completed.counters.captured_packets == ingestion.records_processed
        assert completed.counters.decoded_packets == ingestion.records_processed
        assert completed.counters.flows_reused == 1
        assert completed.counters.detections_created == 1
        assert pause_injected is True

        with database.session() as session:
            source = TelemetrySourceRepository(session).get(ingestion.job_id)
            flows = NetworkFlowRepository(session).list_by_source(ingestion.job_id)
            detections = DetectionResultRepository(session).list()
            alerts = SecurityAlertRepository(session).list()
            groups = AlertGroupRepository(session).list()
            hypotheses = ThreatHypothesisRepository(session).list()
            ledgers = RuntimeOutputLedgerRepository(session).list_for_job(job.job_id)
            actions = [event.action for event in AuditLogRepository(session).list()]
            stored_worker = RuntimeWorkerRepository(session).get("phase-11-worker")
        assert source is not None
        assert len(flows) == 1
        assert len(detections) == 1
        assert len(ledgers) == 1
        assert ledgers[0].flow_id == flows[0].flow_id
        assert ledgers[0].detection_id == detections[0].detection_id
        assert len(alerts) in {0, 1}
        assert all(group.alert_count >= 2 for group in groups)
        assert all(hypothesis.group_id is not None for hypothesis in hypotheses)
        assert stored_worker is not None
        assert stored_worker.status is RuntimeWorkerStatus.STOPPED
        assert {
            "runtime_job_create",
            "runtime_preflight_pinned",
            "runtime_job_claim",
            "runtime_attempt_start",
            "runtime_preflight_succeeded",
            "runtime_completed",
        } <= set(actions)
        assert "runtime_heartbeat" not in actions

        drift_ingestion = _ingest(database, settings)
        drift_job = service.create_replay(drift_ingestion.job_id, speed=1_000.0)
        risk_path = settings.detection.risk_policy_path
        original_risk = risk_path.read_bytes()
        try:
            risk_path.write_bytes(original_risk + b"\n# drift after pinning\n")
            assert RuntimeWorkerProcess(
                database,
                settings=settings,
                runtime_policy=runtime_policy,
                project_root=PROJECT_ROOT,
                worker_id="drift-worker",
            ).run_one_and_stop()
        finally:
            risk_path.write_bytes(original_risk)
        drift_failed = service.get(drift_job.job_id)
        assert drift_failed.status is RuntimeJobStatus.FAILED
        assert drift_failed.progress == 0.0
        assert drift_failed.counters.captured_packets == 0
        assert drift_failed.failure_code == "runtimepreflight"
        assert drift_failed.failure_message is not None
        assert "pinned job snapshot" in drift_failed.failure_message
        assert str(tmp_path) not in drift_failed.failure_message

        malformed_name = "runtime-malformed.pcap"
        malformed_bytes = b"\xd4\xc3\xb2\xa1" + b"\x00" * 8
        malformed_path = settings.ingestion.storage_root / malformed_name
        malformed_path.write_bytes(malformed_bytes)
        malformed_source = TelemetrySource(
            source_id=uuid4(),
            source_type=SourceType.PCAP,
            filename_or_interface="malformed.pcap",
            ingestion_mode=IngestionMode.IMPORT,
            status=LifecycleStatus.COMPLETED,
            records_processed=1,
            checksum=hashlib.sha256(malformed_bytes).hexdigest(),
            source_metadata={"stored_filename": malformed_name},
        )
        with database.session() as session, session.begin():
            TelemetrySourceRepository(session).add(malformed_source)
        with pytest.raises(RuntimePreflightError, match="parser initialization"):
            service.create_replay(malformed_source.source_id, speed=1_000.0)
        with database.session() as session:
            assert RuntimeOutputLedgerRepository(session).list_for_job(
                drift_job.job_id
            ) == ()
            assert RuntimeJobRepository(session).get_by_source(
                malformed_source.source_id
            ) is None
            source_audits = [
                event
                for event in AuditLogRepository(session).list()
                if event.object_id == str(malformed_source.source_id)
            ]
            assert [event.action for event in source_audits] == [
                "runtime_preflight_failed"
            ]
            assert len(DetectionResultRepository(session).list()) == 1

        recovery_ingestion = _ingest(database, settings)
        recovery_job = service.create_replay(
            recovery_ingestion.job_id,
            speed=1_000.0,
        )
        recovery_now = datetime.now(UTC)
        with database.session() as session:
            recovery_source = TelemetrySourceRepository(session).get(
                recovery_ingestion.job_id
            )
            recovery_flows = NetworkFlowRepository(session).list_by_source(
                recovery_ingestion.job_id
            )
        assert recovery_source is not None
        assert len(recovery_flows) == 1
        loaded_recovery = RuntimePreflightVerifier(
            settings=settings,
            runtime_policy=runtime_policy,
            project_root=PROJECT_ROOT,
        ).verify(recovery_source, expected_snapshot=recovery_job.snapshot)
        with database.session() as session, session.begin():
            RuntimeWorkerRepository(session).upsert(
                RuntimeWorker(
                    worker_id="interrupted-worker",
                    status=RuntimeWorkerStatus.IDLE,
                    started_at=recovery_now,
                    heartbeat_at=recovery_now,
                )
            )
            recovery_repository = RuntimeJobRepository(
                session,
                AuditLogRepository(session),
            )
            assert recovery_repository.claim_next(
                worker_id="interrupted-worker",
                now=recovery_now,
                lease_seconds=30,
                actor="interrupted-worker",
            )
            recovery_repository.start_attempt(
                recovery_job.job_id,
                worker_id="interrupted-worker",
                now=recovery_now,
                actor="interrupted-worker",
                maximum_attempts=runtime_policy.policy.worker.maximum_attempts,
            )
            running_recovery = recovery_repository.mark_running(
                recovery_job.job_id,
                worker_id="interrupted-worker",
                now=recovery_now,
                actor="interrupted-worker",
            )
        partial_counters = RuntimePipelineRunner(
            database,
            settings=settings,
            runtime_policy=runtime_policy,
            project_root=PROJECT_ROOT,
            worker_id="interrupted-worker",
            stop_event=threading.Event(),
        )._persist_batch(  # noqa: SLF001
            running_recovery,
            loaded_recovery,
            recovery_flows,
            RuntimeCounters(captured_packets=recovery_ingestion.records_processed),
            progress=0.5,
        )
        assert partial_counters.detections_created == 1
        with database.session() as session, session.begin():
            interrupted = RuntimeJobRepository(
                session,
                AuditLogRepository(session),
            ).interrupt(
                recovery_job.job_id,
                worker_id="interrupted-worker",
                reason="injected after committed batch",
                now=datetime.now(UTC),
                actor="interrupted-worker",
            )
        assert interrupted.status is RuntimeJobStatus.RECOVERY_PENDING
        recovered = service.recover(
            recovery_job.job_id,
            actor="phase-11-e2e",
            reason="verify deterministic origin replay",
        )
        assert recovered.status is RuntimeJobStatus.QUEUED
        assert recovered.failure_code == "interrupted"
        assert RuntimeWorkerProcess(
            database,
            settings=settings,
            runtime_policy=runtime_policy,
            project_root=PROJECT_ROOT,
            worker_id="recovery-worker",
        ).run_one_and_stop()
        recovered_complete = service.get(recovery_job.job_id)
        assert recovered_complete.status is RuntimeJobStatus.COMPLETED
        assert recovered_complete.counters.flows_reused == 1
        assert recovered_complete.counters.detections_reused == 1
        recovery_attempts = service.attempts(recovery_job.job_id)
        assert len(recovery_attempts) == 2
        assert recovery_attempts[0].progress == 0.5
        assert recovery_attempts[1].status.value == "completed"
        with database.session() as session:
            assert len(
                RuntimeOutputLedgerRepository(session).list_for_job(
                    recovery_job.job_id
                )
            ) == 1
            assert len(DetectionResultRepository(session).list()) == 2
        with database.session() as session:
            before_restart = (
                TelemetrySourceRepository(session).get(ingestion.job_id),
                NetworkFlowRepository(session).list_by_source(ingestion.job_id),
                DetectionResultRepository(session).list(),
                SecurityAlertRepository(session).list(),
                AlertGroupRepository(session).list(),
                ThreatHypothesisRepository(session).list(),
                RuntimeOutputLedgerRepository(session).list_for_job(job.job_id),
                RuntimeJobRepository(session).get(job.job_id),
            )
    finally:
        database.dispose()

    restarted = Database(settings.database)
    assert restarted.initialize() == 5
    try:
        with restarted.session() as session:
            after_restart = (
                TelemetrySourceRepository(session).get(ingestion.job_id),
                NetworkFlowRepository(session).list_by_source(ingestion.job_id),
                DetectionResultRepository(session).list(),
                SecurityAlertRepository(session).list(),
                AlertGroupRepository(session).list(),
                ThreatHypothesisRepository(session).list(),
                RuntimeOutputLedgerRepository(session).list_for_job(job.job_id),
                RuntimeJobRepository(session).get(job.job_id),
            )
        assert after_restart == before_restart
        status = RuntimeStatusReader(restarted).read()
        assert status.queue_length == 0
        assert status.running_jobs == 0
        assert status.recovery_pending == 0
        assert status.live_capture_enabled is False
        assert status.automatic_recovery is False
        assert len(status.latest_errors) == 1
        assert status.latest_errors[0]["error_stage"] == "preflight"
        assert status.latest_errors[0]["retryable"] is False
    finally:
        restarted.dispose()
