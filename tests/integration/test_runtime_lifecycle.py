"""Runtime state-machine, claim, lease, pause, and recovery integration tests."""

from __future__ import annotations

import threading
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from aegishunt.config import DatabaseSettings
from aegishunt.runtime.clock import RuntimeClock
from aegishunt.runtime.config import load_runtime_policy
from aegishunt.runtime.contracts import (
    RuntimeCounters,
    RuntimeJobStatus,
    RuntimeWorker,
    RuntimeWorkerStatus,
)
from aegishunt.runtime.control import RuntimeControlMonitor
from aegishunt.runtime.errors import (
    RuntimeStateError,
)
from aegishunt.runtime.repositories import (
    RuntimeJobRepository,
    RuntimeResourceRepository,
    RuntimeWorkerRepository,
)
from aegishunt.runtime.resources import ProcessResourceSampler
from aegishunt.schemas import TelemetrySource
from aegishunt.schemas.enums import IngestionMode, LifecycleStatus, SourceType
from aegishunt.storage import Database
from aegishunt.storage.repositories import (
    AuditLogRepository,
    TelemetrySourceRepository,
)
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


def test_job_lifecycle_pause_resume_interrupt_and_explicit_recovery(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path)
    job = runtime_job()
    try:
        with database.session() as session, session.begin():
            audit = AuditLogRepository(session)
            RuntimeWorkerRepository(session).upsert(_worker())
            stored = RuntimeJobRepository(session, audit).add(job, actor="operator")
            assert stored.status is RuntimeJobStatus.QUEUED

        with database.session() as session, session.begin():
            repository = RuntimeJobRepository(session, AuditLogRepository(session))
            claimed = repository.claim_next(
                worker_id="worker-a",
                now=NOW + timedelta(seconds=1),
                lease_seconds=30,
                actor="worker-a",
            )
            assert claimed is not None
            attempt = repository.start_attempt(
                claimed.job_id,
                worker_id="worker-a",
                now=NOW + timedelta(seconds=1),
                actor="worker-a",
            )
            running = repository.mark_running(
                claimed.job_id,
                worker_id="worker-a",
                now=NOW + timedelta(seconds=2),
                actor="worker-a",
            )
            assert running.current_attempt_id == attempt.attempt_id
            repository.update_progress(
                claimed.job_id,
                worker_id="worker-a",
                counters=RuntimeCounters(captured_packets=2),
                progress=0.5,
                now=NOW + timedelta(seconds=3),
            )
            repository.heartbeat(
                claimed.job_id,
                worker_id="worker-a",
                now=NOW + timedelta(seconds=4),
                lease_seconds=30,
            )
            repository.request_pause(
                claimed.job_id,
                actor="operator",
                now=NOW + timedelta(seconds=5),
            )
            paused = repository.mark_paused(
                claimed.job_id,
                worker_id="worker-a",
                actor="worker-a",
                now=NOW + timedelta(seconds=6),
            )
            assert paused.status is RuntimeJobStatus.PAUSED
            assert repository.resume(
                claimed.job_id,
                actor="operator",
                now=NOW + timedelta(seconds=7),
            ).status is RuntimeJobStatus.RUNNING
            interrupted = repository.interrupt(
                claimed.job_id,
                worker_id="worker-a",
                reason="graceful shutdown",
                actor="worker-a",
                now=NOW + timedelta(seconds=8),
            )
            assert interrupted.status is RuntimeJobStatus.RECOVERY_PENDING
            assert interrupted.claimed_by is None
            assert interrupted.progress == 0.5

        with database.session() as session, session.begin():
            recovered = RuntimeJobRepository(
                session,
                AuditLogRepository(session),
            ).recover(
                job.job_id,
                actor="operator",
                now=NOW + timedelta(seconds=9),
            )
            assert recovered.status is RuntimeJobStatus.QUEUED
            assert recovered.progress == 0.0
            assert recovered.counters == RuntimeCounters()
            assert recovered.recovery_count == 1

        with database.session() as session:
            repository = RuntimeJobRepository(session)
            attempts = repository.list_attempts(job.job_id)
            audit_events = AuditLogRepository(session).list()
            actions = [item.action for item in audit_events]
            resume_request = next(
                item
                for item in audit_events
                if item.action == "runtime_resume_requested"
            )
        assert len(attempts) == 1
        assert attempts[0].status.value == "interrupted"
        assert attempts[0].restart_from_origin is True
        assert "runtime_job_create" in actions
        assert "runtime_job_claim" in actions
        assert "runtime_attempt_start" in actions
        assert "runtime_pause_requested" in actions
        assert "runtime_paused" in actions
        assert "runtime_resumed" in actions
        assert "runtime_interrupted" in actions
        assert "runtime_recovery_requested" in actions
        assert "runtime_heartbeat" not in actions
        assert "runtime_resource_sample" not in actions
        assert resume_request.created_at == NOW + timedelta(seconds=7)
        assert (
            resume_request.details["lifecycle_timestamp"]
            == (NOW + timedelta(seconds=7)).isoformat()
        )
    finally:
        database.dispose()
def test_control_monitor_keeps_paused_job_and_worker_lease_live(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path)
    job = runtime_job()
    monotonic_time = 0.0
    sleep_calls = 0

    def now() -> datetime:
        return NOW + timedelta(seconds=monotonic_time)

    def monotonic() -> float:
        return monotonic_time

    def sleep(_: float) -> None:
        nonlocal monotonic_time, sleep_calls
        sleep_calls += 1
        monotonic_time += 6.0
        if sleep_calls == 2:
            with database.session() as session, session.begin():
                RuntimeJobRepository(
                    session,
                    AuditLogRepository(session),
                ).resume(
                    job.job_id,
                    actor="operator",
                    now=NOW + timedelta(seconds=monotonic_time),
                )

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
            repository.mark_running(
                job.job_id,
                worker_id="worker-a",
                now=NOW,
                actor="worker-a",
            )
            with pytest.raises(RuntimeStateError, match="paused"):
                repository.resume(job.job_id, actor="operator", now=NOW)
            first_request = repository.request_pause(
                job.job_id,
                actor="operator",
                now=NOW + timedelta(seconds=1),
            )
            repeated_request = repository.request_pause(
                job.job_id,
                actor="operator",
                now=NOW + timedelta(seconds=1),
            )
            assert repeated_request == first_request

        monitor = RuntimeControlMonitor(
            database,
            runtime_policy=load_runtime_policy(PROJECT_ROOT / "configs" / "runtime.yaml"),
            worker_id="worker-a",
            stop_event=threading.Event(),
            clock=RuntimeClock(
                now=now,
                monotonic=monotonic,
                sleep=sleep,
            ),
            resource_sampler=ProcessResourceSampler(lambda: object()),
        )
        monitor.check(job.job_id, RuntimeCounters(), 0.0)

        with database.session() as session:
            resumed = RuntimeJobRepository(session).get(job.job_id)
            worker = RuntimeWorkerRepository(session).get("worker-a")
            attempts = RuntimeJobRepository(session).list_attempts(job.job_id)
            samples = RuntimeResourceRepository(session).latest()
        assert resumed is not None
        assert resumed.status is RuntimeJobStatus.RUNNING
        assert resumed.heartbeat_at == NOW + timedelta(seconds=6)
        assert worker is not None
        assert worker.heartbeat_at == NOW + timedelta(seconds=6)
        assert attempts[0].paused_at is not None
        assert attempts[0].resumed_at == NOW + timedelta(seconds=12)
        assert len(samples) == 1
        assert samples[0].monitoring_status == "unavailable"

        with database.session() as session, session.begin():
            repository = RuntimeJobRepository(session, AuditLogRepository(session))
            repository.complete(
                job.job_id,
                worker_id="worker-a",
                counters=RuntimeCounters(),
                now=NOW + timedelta(seconds=13),
                actor="worker-a",
            )
            with pytest.raises(RuntimeStateError, match="running"):
                repository.request_pause(
                    job.job_id,
                    actor="operator",
                    now=NOW + timedelta(seconds=14),
                )
    finally:
        database.dispose()


def test_claim_is_atomic_across_competing_sqlite_sessions(tmp_path: Path) -> None:
    database = _database(tmp_path)
    barrier = threading.Barrier(2)
    claimed: list[str] = []
    failures: list[BaseException] = []
    job = runtime_job()
    try:
        with database.session() as session, session.begin():
            RuntimeJobRepository(session).add(job, actor="operator")

        def contender(worker_id: str) -> None:
            try:
                barrier.wait(timeout=5)
                with database.session() as session, session.begin():
                    result = RuntimeJobRepository(session).claim_next(
                        worker_id=worker_id,
                        now=NOW,
                        lease_seconds=30,
                        actor=worker_id,
                    )
                    if result is not None:
                        claimed.append(worker_id)
            except BaseException as exc:
                failures.append(exc)

        threads = [
            threading.Thread(target=contender, args=(worker_id,))
            for worker_id in ("worker-a", "worker-b")
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        assert failures == []
        assert len(claimed) == 1
        with database.session() as session:
            stored = RuntimeJobRepository(session).get(job.job_id)
        assert stored is not None
        assert stored.status is RuntimeJobStatus.VALIDATING
        assert stored.claimed_by == claimed[0]
    finally:
        database.dispose()


def test_stale_lease_requires_explicit_recovery_and_transaction_rolls_back(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path)
    job = runtime_job()
    try:
        with database.session() as session, session.begin():
            RuntimeWorkerRepository(session).upsert(_worker())
            repository = RuntimeJobRepository(session)
            repository.add(job, actor="operator")
            claimed = repository.claim_next(
                worker_id="worker-a",
                now=NOW,
                lease_seconds=5,
                actor="worker-a",
            )
            assert claimed is not None
            repository.start_attempt(
                job.job_id,
                worker_id="worker-a",
                now=NOW,
                actor="worker-a",
            )
            repository.mark_running(
                job.job_id,
                worker_id="worker-a",
                now=NOW,
                actor="worker-a",
            )

        with (
            pytest.raises(RuntimeError, match="force rollback"),
            database.session() as session,
            session.begin(),
        ):
            RuntimeJobRepository(session).update_progress(
                job.job_id,
                worker_id="worker-a",
                counters=RuntimeCounters(captured_packets=99),
                progress=0.9,
                now=NOW + timedelta(seconds=1),
            )
            raise RuntimeError("force rollback")
        with database.session() as session:
            unchanged = RuntimeJobRepository(session).get(job.job_id)
        assert unchanged is not None
        assert unchanged.progress == 0.0

        with database.session() as session, session.begin():
            stale = RuntimeJobRepository(
                session,
                AuditLogRepository(session),
            ).reconcile_stale(
                now=NOW + timedelta(seconds=6),
                actor="worker-reconciler",
            )
            assert len(stale) == 1
            assert stale[0].status is RuntimeJobStatus.RECOVERY_PENDING
            assert stale[0].failure_code == "stale_worker_lease"
            recovered = RuntimeJobRepository(session).recover(
                job.job_id,
                actor="operator",
                now=NOW + timedelta(seconds=7),
            )
            assert recovered.status is RuntimeJobStatus.QUEUED
    finally:
        database.dispose()


def test_recovery_rejects_permanent_failure_and_attempt_limit(tmp_path: Path) -> None:
    database = _database(tmp_path)
    job = runtime_job()
    try:
        with database.session() as session, session.begin():
            RuntimeWorkerRepository(session).upsert(_worker())
            repository = RuntimeJobRepository(session)
            repository.add(job, actor="operator")
            assert repository.claim_next(
                worker_id="worker-a",
                now=NOW,
                lease_seconds=30,
                actor="worker-a",
            )
            repository.start_attempt(
                job.job_id,
                worker_id="worker-a",
                now=NOW,
                actor="worker-a",
                maximum_attempts=1,
            )
            repository.fail(
                job.job_id,
                worker_id="worker-a",
                code="runtimepreflight",
                message="artifact identity mismatch",
                category="pipeline_preflight",
                retryable=False,
                now=NOW + timedelta(seconds=1),
                actor="worker-a",
            )
            with pytest.raises(RuntimeStateError, match="permanent"):
                repository.recover(
                    job.job_id,
                    actor="operator",
                    now=NOW + timedelta(seconds=2),
                    maximum_attempts=1,
                )

        with database.session() as session, session.begin():
            repository = RuntimeJobRepository(session)
            row = repository._required(job.job_id)  # noqa: SLF001
            row.latest_error_retryable = True
            with pytest.raises(RuntimeStateError, match="attempt limit"):
                repository.recover(
                    job.job_id,
                    actor="operator",
                    now=NOW + timedelta(seconds=3),
                    maximum_attempts=1,
                )
    finally:
        database.dispose()
