"""ORM records for the durable single-node runtime queue and evidence."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import JSON, ForeignKey, Index, String, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from aegishunt.runtime.contracts import (
    RuntimeAttemptStatus,
    RuntimeDesiredAction,
    RuntimeJobStatus,
    RuntimeProgressMode,
    RuntimeStage,
    RuntimeWorkerStatus,
)
from aegishunt.storage.base import Base, UTCDateTime, string_enum


class RuntimeJobRecord(Base):
    __tablename__ = "runtime_jobs"
    __table_args__ = (
        UniqueConstraint("source_id", name="uq_runtime_source_job"),
        Index("ix_runtime_jobs_queue", "status", "created_at"),
        Index("ix_runtime_jobs_lease", "lease_expires_at"),
    )

    job_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    source_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("telemetry_sources.source_id"), nullable=False, index=True
    )
    capture_session_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    status: Mapped[RuntimeJobStatus] = mapped_column(
        string_enum(RuntimeJobStatus, name="runtime_job_status"),
        nullable=False,
        index=True,
    )
    desired_action: Mapped[RuntimeDesiredAction] = mapped_column(
        string_enum(RuntimeDesiredAction, name="runtime_desired_action"),
        nullable=False,
    )
    current_stage: Mapped[RuntimeStage] = mapped_column(
        string_enum(RuntimeStage, name="runtime_stage"),
        nullable=False,
        index=True,
    )
    current_attempt_number: Mapped[int] = mapped_column(nullable=False, default=0)
    replay_speed: Mapped[float] = mapped_column(nullable=False)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    snapshot_checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    runtime_policy_id: Mapped[str] = mapped_column(String(255), nullable=False)
    runtime_policy_version: Mapped[str] = mapped_column(String(128), nullable=False)
    runtime_policy_checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    counters: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    progress_semantics: Mapped[str] = mapped_column(String(64), nullable=False)
    progress_mode: Mapped[RuntimeProgressMode] = mapped_column(
        string_enum(RuntimeProgressMode, name="runtime_progress_mode"),
        nullable=False,
    )
    progress_current: Mapped[int] = mapped_column(nullable=False, default=0)
    progress_total: Mapped[int | None] = mapped_column(nullable=True)
    progress: Mapped[float] = mapped_column(nullable=False, default=0.0)
    observed_counters: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )
    observed_progress_semantics: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    observed_progress_current: Mapped[int] = mapped_column(nullable=False, default=0)
    observed_progress_total: Mapped[int | None] = mapped_column(nullable=True)
    observed_progress: Mapped[float] = mapped_column(nullable=False, default=0.0)
    observed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    claimed_by: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    current_attempt_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    failure_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    failure_message: Mapped[str | None] = mapped_column(String(1_000), nullable=True)
    latest_error_category: Mapped[str | None] = mapped_column(String(128), nullable=True)
    latest_error_stage: Mapped[RuntimeStage | None] = mapped_column(
        string_enum(RuntimeStage, name="runtime_error_stage"),
        nullable=True,
    )
    latest_error_retryable: Mapped[bool | None] = mapped_column(nullable=True)
    latest_error_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    recovery_count: Mapped[int] = mapped_column(nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    job_schema_version: Mapped[str] = mapped_column(String(64), nullable=False)


class RuntimeAttemptRecord(Base):
    __tablename__ = "runtime_attempts"
    __table_args__ = (
        UniqueConstraint("job_id", "attempt_number", name="uq_runtime_job_attempt"),
    )

    attempt_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    job_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("runtime_jobs.job_id"), nullable=False, index=True
    )
    worker_id: Mapped[str] = mapped_column(
        String(255), ForeignKey("runtime_workers.worker_id"), nullable=False, index=True
    )
    attempt_number: Mapped[int] = mapped_column(nullable=False)
    status: Mapped[RuntimeAttemptStatus] = mapped_column(
        string_enum(RuntimeAttemptStatus, name="runtime_attempt_status"),
        nullable=False,
        index=True,
    )
    restart_from_origin: Mapped[bool] = mapped_column(nullable=False)
    counters: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    progress_semantics: Mapped[str] = mapped_column(String(64), nullable=False)
    progress_current: Mapped[int] = mapped_column(nullable=False, default=0)
    progress_total: Mapped[int | None] = mapped_column(nullable=True)
    progress: Mapped[float] = mapped_column(nullable=False, default=0.0)
    observed_counters: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )
    observed_progress_semantics: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    observed_progress_current: Mapped[int] = mapped_column(nullable=False, default=0)
    observed_progress_total: Mapped[int | None] = mapped_column(nullable=True)
    observed_progress: Mapped[float] = mapped_column(nullable=False, default=0.0)
    observed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)
    paused_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    resumed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    interrupted_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    ended_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    interruption_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    error_category: Mapped[str | None] = mapped_column(String(128), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    error_message: Mapped[str | None] = mapped_column(String(1_000), nullable=True)
    error_retryable: Mapped[bool | None] = mapped_column(nullable=True)
    attempt_schema_version: Mapped[str] = mapped_column(String(64), nullable=False)


class RuntimeWorkerRecord(Base):
    __tablename__ = "runtime_workers"

    worker_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    status: Mapped[RuntimeWorkerStatus] = mapped_column(
        string_enum(RuntimeWorkerStatus, name="runtime_worker_status"),
        nullable=False,
        index=True,
    )
    current_job_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    process_identity_summary: Mapped[str] = mapped_column(String(255), nullable=False)
    model_load_state: Mapped[str] = mapped_column(String(64), nullable=False)
    latest_error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    latest_error_summary: Mapped[str | None] = mapped_column(String(1_000), nullable=True)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)
    heartbeat_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    stopped_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    degraded_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    worker_schema_version: Mapped[str] = mapped_column(String(64), nullable=False)


class RuntimeResourceSampleRecord(Base):
    __tablename__ = "runtime_resource_samples"
    __table_args__ = (
        Index("ix_runtime_resource_worker_time", "worker_id", "sampled_at"),
    )

    sample_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    worker_id: Mapped[str] = mapped_column(
        String(255), ForeignKey("runtime_workers.worker_id"), nullable=False, index=True
    )
    job_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("runtime_jobs.job_id"), nullable=True, index=True
    )
    sampled_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)
    process_cpu_percent: Mapped[float | None] = mapped_column(nullable=True)
    process_rss_bytes: Mapped[int | None] = mapped_column(nullable=True)
    system_memory_percent: Mapped[float | None] = mapped_column(nullable=True)
    thread_count: Mapped[int | None] = mapped_column(nullable=True)
    queue_length: Mapped[int] = mapped_column(nullable=False, default=0)
    active_job_count: Mapped[int] = mapped_column(nullable=False, default=0)
    worker_heartbeat_age_seconds: Mapped[float | None] = mapped_column(nullable=True)
    model_load_state: Mapped[str] = mapped_column(String(64), nullable=False)
    sampler_available: Mapped[bool] = mapped_column(nullable=False)
    monitoring_status: Mapped[str] = mapped_column(String(32), nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    resource_sample_schema_version: Mapped[str] = mapped_column(String(64), nullable=False)


class RuntimeOutputLedgerRecord(Base):
    __tablename__ = "runtime_output_ledger"
    __table_args__ = (
        UniqueConstraint("job_id", "flow_id", name="uq_runtime_job_flow_output"),
    )

    ledger_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    job_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("runtime_jobs.job_id"), nullable=False, index=True
    )
    source_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("telemetry_sources.source_id"), nullable=False, index=True
    )
    flow_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("network_flows.flow_id"), nullable=False, index=True
    )
    detection_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("detection_results.detection_id"), nullable=False
    )
    alert_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("security_alerts.alert_id"), nullable=True
    )
    output_checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    stage: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_input_identity: Mapped[str] = mapped_column(String(255), nullable=False)
    output_object_type: Mapped[str] = mapped_column(String(64), nullable=False)
    output_object_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    disposition: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)
