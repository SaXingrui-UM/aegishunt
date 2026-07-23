"""Operator-facing durable runtime job lifecycle service."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

from sqlalchemy.exc import IntegrityError

from aegishunt.config import ApplicationSettings
from aegishunt.runtime.clock import RuntimeClock
from aegishunt.runtime.config import LoadedRuntimePolicy
from aegishunt.runtime.contracts import (
    RuntimeAttempt,
    RuntimeJob,
    RuntimeJobStatus,
    RuntimeProgressMode,
)
from aegishunt.runtime.errors import RuntimePreflightError, RuntimeStateError
from aegishunt.runtime.preflight import RuntimePreflightVerifier
from aegishunt.runtime.repositories import RuntimeJobRepository
from aegishunt.storage import Database
from aegishunt.storage.repositories import AuditLogRepository, TelemetrySourceRepository


class RuntimeJobService:
    """Create only pinned PCAP replay jobs and expose explicit state controls."""

    def __init__(
        self,
        database: Database,
        *,
        settings: ApplicationSettings,
        runtime_policy: LoadedRuntimePolicy,
        project_root: Path,
        clock: RuntimeClock | None = None,
    ) -> None:
        self._database = database
        self._policy = runtime_policy
        self._maximum_jobs_per_query = (
            runtime_policy.policy.worker.maximum_jobs_per_query
        )
        self._clock = clock or RuntimeClock()
        self._preflight = RuntimePreflightVerifier(
            settings=settings,
            runtime_policy=runtime_policy,
            project_root=project_root,
        )

    def create_replay(
        self,
        source_id: UUID,
        *,
        speed: float | None = None,
        actor: str = "runtime-cli",
    ) -> RuntimeJob:
        replay = self._policy.policy.replay
        selected_speed = replay.default_speed if speed is None else speed
        if not replay.minimum_speed <= selected_speed <= replay.maximum_speed:
            raise RuntimeStateError("replay speed is outside configured bounds")
        with self._database.session() as session:
            source = TelemetrySourceRepository(session).get(source_id)
            existing = RuntimeJobRepository(session).get_by_source(source_id)
        if source is None:
            raise RuntimeStateError("telemetry source does not exist")
        if existing is not None:
            raise RuntimeStateError(
                "telemetry source already has a runtime job; use explicit recovery"
            )
        try:
            loaded = self._preflight.verify(source)
        except RuntimePreflightError:
            failed_at = self._clock.now()
            with self._database.session() as session, session.begin():
                AuditLogRepository(session).record(
                    actor=actor,
                    action="runtime_preflight_failed",
                    object_type="telemetry_sources",
                    object_id=str(source_id),
                    details={
                        "source_id": str(source_id),
                        "stage": "preflight",
                        "retryable": False,
                        "reason": "source or pipeline verification failed",
                        "source": "runtime",
                        "before_state": "source_selected",
                        "after_state": "preflight_rejected",
                        "lifecycle_timestamp": failed_at.isoformat(),
                        "operation_id": (
                            f"runtime_preflight_failed:{source_id}:"
                            f"{failed_at.isoformat()}"
                        ),
                    },
                    created_at=failed_at,
                )
            raise
        now = self._clock.now()
        job = RuntimeJob(
            source_id=source_id,
            replay_speed=selected_speed,
            snapshot=loaded.snapshot,
            progress_mode=(
                RuntimeProgressMode.PACKET_COUNT
                if loaded.snapshot.verified_packet_count is not None
                else RuntimeProgressMode.INDETERMINATE
            ),
            progress_total=loaded.snapshot.verified_packet_count,
            created_at=now,
            updated_at=now,
        )
        try:
            with self._database.session() as session, session.begin():
                audit = AuditLogRepository(session)
                stored = RuntimeJobRepository(session, audit).add(job, actor=actor)
                audit.record(
                    actor=actor,
                    action="runtime_preflight_pinned",
                    object_type="runtime_jobs",
                    object_id=str(stored.job_id),
                    details={
                        "source_id": str(source_id),
                        "source_checksum": stored.snapshot.source_checksum,
                        "runtime_policy_id": stored.snapshot.runtime_policy_id,
                        "runtime_policy_version": stored.snapshot.runtime_policy_version,
                        "artifact_count": len(stored.snapshot.artifacts),
                        "snapshot_checksum": stored.snapshot_checksum,
                        "source": "runtime",
                        "before_state": "preflight_verified",
                        "after_state": "queued",
                        "reason": "runtime pipeline snapshot pinned",
                        "retryable": None,
                        "lifecycle_timestamp": now.isoformat(),
                        "operation_id": (
                            f"runtime_preflight_pinned:{stored.job_id}:"
                            f"{now.isoformat()}"
                        ),
                    },
                    created_at=now,
                )
                return stored
        except IntegrityError as exc:
            raise RuntimeStateError(
                "telemetry source already has a runtime job; use explicit recovery"
            ) from exc

    def get(self, job_id: UUID) -> RuntimeJob:
        with self._database.session() as session:
            job = RuntimeJobRepository(session).get(job_id)
        if job is None:
            raise RuntimeStateError("runtime job does not exist")
        return job

    def list(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        status: RuntimeJobStatus | None = None,
    ) -> tuple[list[RuntimeJob], int]:
        if limit > self._maximum_jobs_per_query:
            raise RuntimeStateError("runtime job query exceeds the configured limit")
        with self._database.session() as session:
            return RuntimeJobRepository(session).list(
                limit=limit,
                offset=offset,
                status=status,
            )

    def attempts(self, job_id: UUID) -> tuple[RuntimeAttempt, ...]:
        with self._database.session() as session:
            repository = RuntimeJobRepository(session)
            if repository.get(job_id) is None:
                raise RuntimeStateError("runtime job does not exist")
            return repository.list_attempts(job_id)

    def pause(
        self,
        job_id: UUID,
        *,
        actor: str = "runtime-cli",
        reason: str = "operator requested pause",
    ) -> RuntimeJob:
        with self._database.session() as session, session.begin():
            audit = AuditLogRepository(session)
            return RuntimeJobRepository(session, audit).request_pause(
                job_id,
                actor=actor,
                reason=reason,
                now=self._clock.now(),
            )

    def resume(
        self,
        job_id: UUID,
        *,
        actor: str = "runtime-cli",
        reason: str = "operator requested resume",
    ) -> RuntimeJob:
        with self._database.session() as session, session.begin():
            audit = AuditLogRepository(session)
            return RuntimeJobRepository(session, audit).resume(
                job_id,
                actor=actor,
                reason=reason,
                now=self._clock.now(),
            )

    def recover(
        self,
        job_id: UUID,
        *,
        actor: str = "runtime-cli",
        reason: str = "operator requested explicit origin recovery",
    ) -> RuntimeJob:
        job = self.get(job_id)
        with self._database.session() as session:
            source = TelemetrySourceRepository(session).get(job.source_id)
        if source is None:
            raise RuntimeStateError("runtime source does not exist")
        self._preflight.verify(source, expected_snapshot=job.snapshot)
        with self._database.session() as session, session.begin():
            audit = AuditLogRepository(session)
            return RuntimeJobRepository(session, audit).recover(
                job_id,
                actor=actor,
                reason=reason,
                maximum_attempts=self._policy.policy.worker.maximum_attempts,
                now=self._clock.now(),
            )
