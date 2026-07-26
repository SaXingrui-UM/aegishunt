"""Offline Phase 11 source-to-hypothesis runtime and restart E2E."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest

from aegishunt.config import ApplicationSettings, DatabaseSettings
from aegishunt.ingestion.schemas import IngestionJob
from aegishunt.ingestion.service import IngestionService
from aegishunt.runtime.clock import RuntimeClock
from aegishunt.runtime.config import LoadedRuntimePolicy
from aegishunt.runtime.contracts import (
    RuntimeCounters,
    RuntimeJob,
    RuntimeJobStatus,
    RuntimeWorker,
    RuntimeWorkerStatus,
)
from aegishunt.runtime.control import RuntimeControlMonitor
from aegishunt.runtime.errors import (
    ReplayInterrupted,
    RuntimePreflightError,
    RuntimeStateError,
)
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
from tests.fixtures.packets import at, tcp_ipv4_frame, write_pcap
from tests.fixtures.runtime import PROJECT_ROOT, build_verified_runtime_environment

SAMPLE_PCAP = PROJECT_ROOT / "data" / "sample" / "phase2-benign.pcap"


def _ingest(
    database: Database,
    settings: ApplicationSettings,
    source_path: Path = SAMPLE_PCAP,
) -> IngestionJob:
    return IngestionService(
        database,
        settings.ingestion,
        flow_settings=settings.flows,
    ).ingest_path(
        source_path,
        source_type=SourceType.PCAP,
        content_type="application/vnd.tcpdump.pcap",
        actor="phase-11-e2e",
    )


def _controlled_correlating_pcap(path: Path) -> Path:
    packets = []
    source_ip = "192.0.2.10"
    for index in range(3):
        destination_ip = f"198.51.100.{20 + index}"
        source_port = 40_000 + index
        packets.extend(
            (
                (
                    at(float(index)),
                    tcp_ipv4_frame(
                        source_ip=source_ip,
                        destination_ip=destination_ip,
                        source_port=source_port,
                        destination_port=443,
                        flags=0x02,
                    ),
                ),
                (
                    at(float(index) + 0.15),
                    tcp_ipv4_frame(
                        source_ip=destination_ip,
                        destination_ip=source_ip,
                        source_port=443,
                        destination_port=source_port,
                        flags=0x04,
                    ),
                ),
            )
        )
    return write_pcap(path, packets)


def _mixed_committed_and_open_pcap(path: Path) -> Path:
    """Expire one flow while retaining a second flow in aggregator memory."""

    return write_pcap(
        path,
        (
            (
                at(0.0),
                tcp_ipv4_frame(
                    source_ip="192.0.2.10",
                    destination_ip="198.51.100.20",
                    source_port=40_000,
                    destination_port=443,
                    flags=0x10,
                ),
            ),
            (
                at(61.0),
                tcp_ipv4_frame(
                    source_ip="192.0.2.30",
                    destination_ip="198.51.100.40",
                    source_port=50_000,
                    destination_port=53,
                    flags=0x10,
                ),
            ),
            (
                at(61.1),
                tcp_ipv4_frame(
                    source_ip="192.0.2.30",
                    destination_ip="198.51.100.40",
                    source_port=50_000,
                    destination_port=53,
                    flags=0x10,
                ),
            ),
        ),
    )


def _single_batch_runtime_policy(
    runtime_policy: LoadedRuntimePolicy,
) -> LoadedRuntimePolicy:
    policy = runtime_policy.policy.model_copy(
        update={
            "worker": runtime_policy.policy.worker.model_copy(
                update={
                    "persistence_batch_size": 1,
                    "progress_update_packet_interval": 1,
                }
            )
        }
    )
    checksum = hashlib.sha256(
        json.dumps(
            policy.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return LoadedRuntimePolicy(policy=policy, configuration_checksum=checksum)


def test_phase_11_replay_persists_verified_pipeline_and_survives_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings, runtime_policy = build_verified_runtime_environment(tmp_path)
    database = Database(settings.database)
    assert database.initialize() == 5
    try:
        ingestion = _ingest(
            database,
            settings,
            _controlled_correlating_pcap(tmp_path / "correlating-runtime.pcap"),
        )
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
        original_complete = RuntimeJobRepository.complete
        pause_injected = False
        paused_snapshots: list[RuntimeJob] = []
        completion_gate_seen = False
        resume_errors: list[BaseException] = []

        def complete_after_downstream(
            repository: RuntimeJobRepository,
            job_id: UUID,
            **kwargs: Any,
        ) -> RuntimeJob:
            nonlocal completion_gate_seen
            if job_id == job.job_id:
                before = repository.get(job_id)
                assert before is not None
                assert before.status is RuntimeJobStatus.RUNNING
                assert before.progress < 1.0
                assert before.progress_current == 0
                assert AlertGroupRepository(
                    repository._session  # noqa: SLF001 - same transaction gate
                ).list()
                assert ThreatHypothesisRepository(
                    repository._session  # noqa: SLF001 - same transaction gate
                ).list()
                completion_gate_seen = True
            completed = original_complete(repository, job_id, **kwargs)
            if job_id == job.job_id:
                assert completed.status is RuntimeJobStatus.COMPLETED
                assert completed.progress == 1.0
            return completed

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
                            paused_snapshots.append(service.get(job.job_id))
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
        monkeypatch.setattr(RuntimeJobRepository, "complete", complete_after_downstream)
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
        assert completed.counters.flows_reused == 3
        assert completed.counters.detections_created == 3
        assert completed.counters.alerts_created >= 2
        assert completed.counters.groups_created >= 1
        assert completed.counters.hypotheses_created >= 1
        assert pause_injected is True
        assert completion_gate_seen is True
        assert len(paused_snapshots) == 1
        paused_snapshot = paused_snapshots[0]
        assert paused_snapshot.current_attempt_id == completed.current_attempt_id
        assert paused_snapshot.observed_progress > 0.0
        assert paused_snapshot.progress == 0.0
        assert paused_snapshot.counters == RuntimeCounters()

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
        assert len(flows) == 3
        assert len(detections) == 3
        assert len(ledgers) == 3
        assert {item.flow_id for item in ledgers} == {
            item.flow_id for item in flows
        }
        assert {item.detection_id for item in ledgers} == {
            item.detection_id for item in detections
        }
        assert len(alerts) >= 2
        assert len(groups) >= 1
        assert len(hypotheses) >= 1
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

        mixed_database = Database(
            DatabaseSettings(url=f"sqlite:///{tmp_path / 'mixed-runtime.sqlite3'}")
        )
        assert mixed_database.initialize() == 5
        mixed_policy = _single_batch_runtime_policy(runtime_policy)
        mixed_settings = settings.model_copy(
            update={
                "database": DatabaseSettings(
                    url=f"sqlite:///{tmp_path / 'mixed-runtime.sqlite3'}"
                )
            }
        )
        mixed_source_id = uuid4()
        mixed_filename = "mixed-committed-open.pcap"
        mixed_path = _mixed_committed_and_open_pcap(
            settings.ingestion.storage_root / mixed_filename
        )
        mixed_bytes = mixed_path.read_bytes()
        mixed_source = TelemetrySource(
            source_id=mixed_source_id,
            source_type=SourceType.PCAP,
            filename_or_interface=mixed_filename,
            ingestion_mode=IngestionMode.IMPORT,
            status=LifecycleStatus.COMPLETED,
            records_processed=3,
            checksum=hashlib.sha256(mixed_bytes).hexdigest(),
            source_metadata={
                "stored_filename": mixed_filename,
                "byte_size": len(mixed_bytes),
            },
        )
        try:
            with mixed_database.session() as session, session.begin():
                TelemetrySourceRepository(session).add(mixed_source)
                RuntimeWorkerRepository(session).upsert(
                    RuntimeWorker(
                        worker_id="mixed-worker",
                        status=RuntimeWorkerStatus.IDLE,
                    )
                )
            mixed_service = RuntimeJobService(
                mixed_database,
                settings=mixed_settings,
                runtime_policy=mixed_policy,
                project_root=PROJECT_ROOT,
            )
            mixed_job = mixed_service.create_replay(
                mixed_source_id,
                speed=mixed_policy.policy.replay.maximum_speed,
                actor="phase-11-e2e",
            )
            with mixed_database.session() as session, session.begin():
                mixed_repository = RuntimeJobRepository(
                    session,
                    AuditLogRepository(session),
                )
                claimed_mixed = mixed_repository.claim_next(
                    worker_id="mixed-worker",
                    now=datetime.now(UTC),
                    lease_seconds=mixed_policy.policy.worker.lease_seconds,
                    actor="mixed-worker",
                )
                assert claimed_mixed is not None
                mixed_repository.start_attempt(
                    mixed_job.job_id,
                    worker_id="mixed-worker",
                    now=datetime.now(UTC),
                    actor="mixed-worker",
                )
            mixed_stop = threading.Event()
            mixed_runner = RuntimePipelineRunner(
                mixed_database,
                settings=mixed_settings,
                runtime_policy=mixed_policy,
                project_root=PROJECT_ROOT,
                worker_id="mixed-worker",
                stop_event=mixed_stop,
                clock=RuntimeClock(sleep=lambda _: None),
            )
            original_mixed_check = mixed_runner._control.check  # noqa: SLF001

            def stop_with_second_flow_open(
                job_id: UUID,
                counters: RuntimeCounters,
                progress: float,
            ) -> None:
                original_mixed_check(job_id, counters, progress)
                if counters.captured_packets == 2:
                    mixed_stop.set()

            monkeypatch.setattr(
                mixed_runner._control,  # noqa: SLF001 - controlled F3 boundary
                "check",
                stop_with_second_flow_open,
            )
            with pytest.raises(ReplayInterrupted, match="shutdown"):
                mixed_runner.run(claimed_mixed)
            with mixed_database.session() as session:
                mixed_persisted = RuntimeJobRepository(session).get(
                    mixed_job.job_id
                )
                mixed_flows = NetworkFlowRepository(session).list_by_source(
                    mixed_source_id
                )
                mixed_ledgers = RuntimeOutputLedgerRepository(session).list_for_job(
                    mixed_job.job_id
                )
            assert mixed_persisted is not None
            assert mixed_persisted.observed_counters.captured_packets == 2
            assert mixed_persisted.observed_progress == pytest.approx(2 / 3)
            assert mixed_persisted.progress == 0.0
            assert mixed_persisted.progress_current == 0
            assert mixed_persisted.counters.captured_packets == 0
            assert mixed_persisted.counters.flows_created == 1
            assert mixed_persisted.counters.detections_created == 1
            assert len(mixed_flows) == 1
            assert len(mixed_ledgers) == 1
        finally:
            mixed_database.dispose()

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
            assert len(DetectionResultRepository(session).list()) == 3

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
            recovery_repository.update_observed_progress(
                recovery_job.job_id,
                worker_id="interrupted-worker",
                counters=RuntimeCounters(
                    captured_packets=recovery_ingestion.records_processed,
                    decoded_packets=recovery_ingestion.records_processed,
                ),
                progress=0.5,
                now=recovery_now,
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
            RuntimeCounters(),
        )
        assert partial_counters.detections_created == 1
        with database.session() as session:
            mixed_evidence = RuntimeJobRepository(session).get(recovery_job.job_id)
            original_ledgers = RuntimeOutputLedgerRepository(session).list_for_job(
                recovery_job.job_id
            )
            original_detection = DetectionResultRepository(session).get(
                original_ledgers[0].detection_id
            )
        assert mixed_evidence is not None
        assert mixed_evidence.progress == 0.0
        assert mixed_evidence.progress_current == 0
        assert mixed_evidence.counters.flows_reused == 1
        assert mixed_evidence.counters.detections_created == 1
        assert mixed_evidence.observed_progress == 0.5
        assert mixed_evidence.observed_counters.captured_packets == (
            recovery_ingestion.records_processed
        )
        assert mixed_evidence.progress != mixed_evidence.observed_progress
        assert len(original_ledgers) == 1
        assert original_detection is not None
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
        assert recovered.progress == 0.0
        assert recovered.observed_progress == 0.0
        assert recovered.counters == RuntimeCounters()
        assert recovered.observed_counters == RuntimeCounters()
        with database.session() as session, session.begin():
            RuntimeWorkerRepository(session).upsert(
                RuntimeWorker(
                    worker_id="recovery-worker",
                    status=RuntimeWorkerStatus.IDLE,
                    started_at=datetime.now(UTC),
                    heartbeat_at=datetime.now(UTC),
                )
            )
            recovery_repository = RuntimeJobRepository(
                session,
                AuditLogRepository(session),
            )
            claimed_recovery = recovery_repository.claim_next(
                worker_id="recovery-worker",
                now=datetime.now(UTC),
                lease_seconds=runtime_policy.policy.worker.lease_seconds,
                actor="recovery-worker",
            )
            assert claimed_recovery is not None
            new_attempt = recovery_repository.start_attempt(
                recovery_job.job_id,
                worker_id="recovery-worker",
                now=datetime.now(UTC),
                actor="recovery-worker",
                maximum_attempts=runtime_policy.policy.worker.maximum_attempts,
            )
            assert new_attempt.progress == 0.0
            assert new_attempt.observed_progress == 0.0
            assert new_attempt.counters == RuntimeCounters()
            assert new_attempt.observed_counters == RuntimeCounters()
            assert new_attempt.restart_from_origin is True
        RuntimePipelineRunner(
            database,
            settings=settings,
            runtime_policy=runtime_policy,
            project_root=PROJECT_ROOT,
            worker_id="recovery-worker",
            stop_event=threading.Event(),
        ).run(claimed_recovery)
        recovered_complete = service.get(recovery_job.job_id)
        assert recovered_complete.status is RuntimeJobStatus.COMPLETED
        assert recovered_complete.counters.flows_reused == 1
        assert recovered_complete.counters.detections_reused == 1
        recovery_attempts = service.attempts(recovery_job.job_id)
        assert len(recovery_attempts) == 2
        assert recovery_attempts[0].progress == 0.0
        assert recovery_attempts[0].observed_progress == 0.5
        assert recovery_attempts[0].observed_counters.captured_packets == (
            recovery_ingestion.records_processed
        )
        assert recovery_attempts[1].observed_progress == 1.0
        assert recovery_attempts[1].status.value == "completed"
        with database.session() as session:
            recovered_ledgers = RuntimeOutputLedgerRepository(session).list_for_job(
                recovery_job.job_id
            )
            recovered_detection = DetectionResultRepository(session).get(
                recovered_ledgers[0].detection_id
            )
            assert len(recovered_ledgers) == 1
            assert recovered_ledgers == original_ledgers
            assert recovered_detection == original_detection
            assert len(DetectionResultRepository(session).list()) == 4
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
