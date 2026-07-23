"""Validated durable contracts for jobs, attempts, workers, resources, and output."""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal, Self
from uuid import UUID, uuid4

from pydantic import Field, field_validator, model_validator

from aegishunt.schemas.base import CoreSchema, JsonObject, require_aware_utc, utc_now
from aegishunt.schemas.enums import SourceType

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class RuntimeJobStatus(StrEnum):
    QUEUED = "queued"
    VALIDATING = "validating"
    RUNNING = "running"
    PAUSE_REQUESTED = "pause_requested"
    PAUSED = "paused"
    RECOVERY_PENDING = "recovery_pending"
    COMPLETED = "completed"
    FAILED = "failed"


class RuntimeAttemptStatus(StrEnum):
    RUNNING = "running"
    PAUSED = "paused"
    INTERRUPTED = "interrupted"
    COMPLETED = "completed"
    FAILED = "failed"


class RuntimeWorkerStatus(StrEnum):
    STARTING = "starting"
    IDLE = "idle"
    BUSY = "busy"
    STOPPING = "stopping"
    STOPPED = "stopped"
    DEGRADED = "degraded"
    FAILED = "failed"


class RuntimeDesiredAction(StrEnum):
    RUN = "run"
    PAUSE = "pause"


class RuntimeStage(StrEnum):
    QUEUED = "queued"
    PREFLIGHT = "preflight"
    REPLAY = "replay"
    CORRELATION = "correlation"
    COMPLETION = "completion"
    RECOVERY = "recovery"
    FAILED = "failed"


class RuntimeProgressMode(StrEnum):
    PACKET_COUNT = "packet_count"
    INDETERMINATE = "indeterminate"


class RuntimeCounters(CoreSchema):
    captured_packets: int = Field(default=0, ge=0)
    decoded_packets: int = Field(default=0, ge=0)
    skipped_packets: int = Field(default=0, ge=0)
    out_of_order_packets: int = Field(default=0, ge=0)
    capped_gaps: int = Field(default=0, ge=0)
    flows_created: int = Field(default=0, ge=0)
    flows_reused: int = Field(default=0, ge=0)
    detections_created: int = Field(default=0, ge=0)
    detections_reused: int = Field(default=0, ge=0)
    alerts_created: int = Field(default=0, ge=0)
    alerts_reused: int = Field(default=0, ge=0)
    groups_created: int = Field(default=0, ge=0)
    groups_reused: int = Field(default=0, ge=0)
    hypotheses_created: int = Field(default=0, ge=0)
    hypotheses_reused: int = Field(default=0, ge=0)


class RuntimeArtifactIdentity(CoreSchema):
    artifact_type: Literal[
        "supervised_model",
        "anomaly_model",
        "fusion_policy",
        "risk_policy",
        "explanation_artifact",
        "correlation_policy",
        "flow_configuration",
    ]
    artifact_id: str = Field(min_length=1, max_length=255)
    version: str = Field(min_length=1, max_length=128)
    checksum: str

    @field_validator("checksum")
    @classmethod
    def validate_checksum(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not _SHA256.fullmatch(normalized):
            raise ValueError("runtime artifact checksum must be SHA-256")
        return normalized


class RuntimePipelineSnapshot(CoreSchema):
    snapshot_schema_version: Literal["1.0.0"] = "1.0.0"
    source_id: UUID
    source_checksum: str
    source_type: SourceType
    stored_filename: str
    source_size_bytes: int = Field(ge=1)
    verified_packet_count: int | None = Field(default=None, ge=1)
    capture_session_id: str = Field(min_length=1, max_length=255)
    feature_schema_version: str = Field(min_length=1, max_length=64)
    artifacts: tuple[RuntimeArtifactIdentity, ...] = Field(min_length=7, max_length=7)
    runtime_policy_id: str
    runtime_policy_version: str
    runtime_policy_checksum: str
    git_commit_sha: str | None = Field(default=None, max_length=64)
    database_schema_version: int = Field(ge=1)
    output_identity_policy: Literal[
        "deterministic_domain_ids_with_verified_runtime_ledger"
    ] = "deterministic_domain_ids_with_verified_runtime_ledger"

    @field_validator("source_checksum", "runtime_policy_checksum")
    @classmethod
    def validate_checksum(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not _SHA256.fullmatch(normalized):
            raise ValueError("runtime snapshot checksum must be SHA-256")
        return normalized

    @field_validator("stored_filename")
    @classmethod
    def validate_logical_filename(cls, value: str) -> str:
        if Path(value).name != value or "/" in value or "\\" in value or value in {"", ".", ".."}:
            raise ValueError("runtime snapshot stores only a logical source filename")
        return value

    @model_validator(mode="after")
    def validate_artifacts(self) -> Self:
        kinds = tuple(item.artifact_type for item in self.artifacts)
        expected = tuple(
            sorted(
                (
                    "supervised_model",
                    "anomaly_model",
                    "fusion_policy",
                    "risk_policy",
                    "explanation_artifact",
                    "correlation_policy",
                    "flow_configuration",
                )
            )
        )
        if tuple(sorted(kinds)) != expected:
            raise ValueError("runtime snapshot requires one exact identity per pipeline component")
        return self


def runtime_snapshot_checksum(snapshot: RuntimePipelineSnapshot) -> str:
    """Return the canonical SHA-256 identity of an immutable runtime snapshot."""

    payload = json.dumps(
        snapshot.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()


class RuntimeJob(CoreSchema):
    job_id: UUID = Field(default_factory=uuid4)
    source_id: UUID
    capture_session_id: str = Field(default="", max_length=255)
    status: RuntimeJobStatus = RuntimeJobStatus.QUEUED
    desired_action: RuntimeDesiredAction = RuntimeDesiredAction.RUN
    current_stage: RuntimeStage = RuntimeStage.QUEUED
    current_attempt_number: int = Field(default=0, ge=0)
    replay_speed: float = Field(gt=0.0)
    snapshot: RuntimePipelineSnapshot
    snapshot_checksum: str = ""
    runtime_policy_id: str = ""
    runtime_policy_version: str = ""
    runtime_policy_checksum: str = ""
    counters: RuntimeCounters = Field(default_factory=RuntimeCounters)
    progress_mode: RuntimeProgressMode = RuntimeProgressMode.INDETERMINATE
    progress_current: int = Field(default=0, ge=0)
    progress_total: int | None = Field(default=None, ge=1)
    progress: float = Field(default=0.0, ge=0.0, le=1.0)
    claimed_by: str | None = Field(default=None, max_length=255)
    lease_expires_at: datetime | None = None
    heartbeat_at: datetime | None = None
    current_attempt_id: UUID | None = None
    failure_code: str | None = Field(default=None, max_length=128)
    failure_message: str | None = Field(default=None, max_length=1_000)
    latest_error_category: str | None = Field(default=None, max_length=128)
    latest_error_stage: RuntimeStage | None = None
    latest_error_retryable: bool | None = None
    latest_error_at: datetime | None = None
    recovery_count: int = Field(default=0, ge=0)
    created_at: datetime = Field(default_factory=utc_now)
    started_at: datetime | None = None
    updated_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
    job_schema_version: Literal["1.0.0"] = "1.0.0"

    @field_validator(
        "lease_expires_at",
        "heartbeat_at",
        "latest_error_at",
        "created_at",
        "started_at",
        "updated_at",
        "completed_at",
    )
    @classmethod
    def validate_time(cls, value: datetime | None) -> datetime | None:
        return None if value is None else require_aware_utc(value)

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        expected_snapshot_checksum = runtime_snapshot_checksum(self.snapshot)
        if not self.snapshot_checksum:
            object.__setattr__(self, "snapshot_checksum", expected_snapshot_checksum)
        elif self.snapshot_checksum != expected_snapshot_checksum:
            raise ValueError("runtime job snapshot checksum does not match its snapshot")
        for field, expected in (
            ("runtime_policy_id", self.snapshot.runtime_policy_id),
            ("runtime_policy_version", self.snapshot.runtime_policy_version),
            ("runtime_policy_checksum", self.snapshot.runtime_policy_checksum),
        ):
            current = getattr(self, field)
            if not current:
                object.__setattr__(self, field, expected)
            elif current != expected:
                raise ValueError("runtime job policy identity differs from its snapshot")
        if self.snapshot.source_id != self.source_id:
            raise ValueError("runtime job source differs from its pinned snapshot")
        if not self.capture_session_id:
            object.__setattr__(
                self,
                "capture_session_id",
                self.snapshot.capture_session_id,
            )
        elif self.capture_session_id != self.snapshot.capture_session_id:
            raise ValueError("runtime job capture session differs from its snapshot")
        if self.updated_at < self.created_at:
            raise ValueError("runtime job update cannot precede creation")
        leased = self.status in {
            RuntimeJobStatus.VALIDATING,
            RuntimeJobStatus.RUNNING,
            RuntimeJobStatus.PAUSE_REQUESTED,
            RuntimeJobStatus.PAUSED,
        }
        fields = (self.claimed_by, self.lease_expires_at, self.heartbeat_at)
        if leased and not all(fields):
            raise ValueError("claimed runtime states require complete lease identity")
        if not leased and any(fields):
            raise ValueError("unclaimed runtime states cannot retain a lease")
        if self.progress_mode is RuntimeProgressMode.PACKET_COUNT:
            if self.progress_total is None:
                raise ValueError("packet-count progress requires a verified total")
            if self.progress_current > self.progress_total:
                raise ValueError("runtime progress cannot exceed its verified total")
        elif self.progress_total is not None:
            raise ValueError("indeterminate progress cannot claim a total")
        if self.status is RuntimeJobStatus.COMPLETED and self.progress != 1.0:
            raise ValueError("completed runtime jobs require complete progress")
        if self.status is not RuntimeJobStatus.COMPLETED and self.progress == 1.0:
            raise ValueError("only completed runtime jobs may report 100 percent")
        if self.status is RuntimeJobStatus.COMPLETED and self.completed_at is None:
            raise ValueError("completed runtime jobs require a completion timestamp")
        if self.status is not RuntimeJobStatus.COMPLETED and self.completed_at is not None:
            raise ValueError("non-completed runtime jobs cannot have a completion timestamp")
        return self


class RuntimeAttempt(CoreSchema):
    attempt_id: UUID = Field(default_factory=uuid4)
    job_id: UUID
    worker_id: str = Field(min_length=1, max_length=255)
    attempt_number: int = Field(ge=1)
    status: RuntimeAttemptStatus = RuntimeAttemptStatus.RUNNING
    restart_from_origin: bool = True
    counters: RuntimeCounters = Field(default_factory=RuntimeCounters)
    progress_current: int = Field(default=0, ge=0)
    progress_total: int | None = Field(default=None, ge=1)
    progress: float = Field(default=0.0, ge=0.0, le=1.0)
    started_at: datetime = Field(default_factory=utc_now)
    paused_at: datetime | None = None
    resumed_at: datetime | None = None
    interrupted_at: datetime | None = None
    completed_at: datetime | None = None
    updated_at: datetime = Field(default_factory=utc_now)
    ended_at: datetime | None = None
    interruption_reason: str | None = Field(default=None, max_length=512)
    error_category: str | None = Field(default=None, max_length=128)
    error_code: str | None = Field(default=None, max_length=128)
    error_message: str | None = Field(default=None, max_length=1_000)
    error_retryable: bool | None = None
    attempt_schema_version: Literal["1.0.0"] = "1.0.0"

    @field_validator(
        "started_at",
        "paused_at",
        "resumed_at",
        "interrupted_at",
        "completed_at",
        "updated_at",
        "ended_at",
    )
    @classmethod
    def validate_time(cls, value: datetime | None) -> datetime | None:
        return None if value is None else require_aware_utc(value)

    @model_validator(mode="after")
    def validate_order(self) -> Self:
        if self.updated_at < self.started_at:
            raise ValueError("attempt update cannot precede start")
        if self.ended_at is not None and self.ended_at < self.started_at:
            raise ValueError("attempt end cannot precede start")
        if self.status is RuntimeAttemptStatus.COMPLETED and self.progress != 1.0:
            raise ValueError("completed runtime attempts require complete progress")
        return self


class RuntimeWorker(CoreSchema):
    worker_id: str = Field(min_length=1, max_length=255)
    status: RuntimeWorkerStatus = RuntimeWorkerStatus.STARTING
    current_job_id: UUID | None = None
    process_identity_summary: str = Field(default="local-process", max_length=255)
    model_load_state: Literal["not_loaded", "verified_per_job_preflight"] = "not_loaded"
    latest_error_code: str | None = Field(default=None, max_length=128)
    latest_error_summary: str | None = Field(default=None, max_length=1_000)
    started_at: datetime = Field(default_factory=utc_now)
    heartbeat_at: datetime = Field(default_factory=utc_now)
    stopped_at: datetime | None = None
    degraded_reason: str | None = Field(default=None, max_length=512)
    worker_schema_version: Literal["1.0.0"] = "1.0.0"

    @field_validator("started_at", "heartbeat_at", "stopped_at")
    @classmethod
    def validate_time(cls, value: datetime | None) -> datetime | None:
        return None if value is None else require_aware_utc(value)


class RuntimeResourceSample(CoreSchema):
    sample_id: UUID = Field(default_factory=uuid4)
    worker_id: str = Field(min_length=1, max_length=255)
    job_id: UUID | None = None
    sampled_at: datetime = Field(default_factory=utc_now)
    process_cpu_percent: float | None = Field(default=None, ge=0.0)
    process_rss_bytes: int | None = Field(default=None, ge=0)
    system_memory_percent: float | None = Field(default=None, ge=0.0, le=100.0)
    thread_count: int | None = Field(default=None, ge=1)
    queue_length: int = Field(default=0, ge=0)
    active_job_count: int = Field(default=0, ge=0)
    worker_heartbeat_age_seconds: float | None = Field(default=None, ge=0.0)
    model_load_state: Literal["not_loaded", "verified_per_job_preflight"] = "not_loaded"
    sampler_available: bool
    monitoring_status: Literal["available", "unavailable"]
    error_code: str | None = Field(default=None, max_length=128)
    resource_sample_schema_version: Literal["1.0.0"] = "1.0.0"

    @field_validator("sampled_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return require_aware_utc(value)

    @model_validator(mode="after")
    def validate_availability(self) -> Self:
        values = (
            self.process_cpu_percent,
            self.process_rss_bytes,
            self.system_memory_percent,
            self.thread_count,
        )
        if self.sampler_available and any(value is None for value in values):
            raise ValueError("available resource samples require complete measurements")
        if not self.sampler_available and any(value is not None for value in values):
            raise ValueError("unavailable resource samples must use null measurements")
        if self.process_cpu_percent is not None and not math.isfinite(
            self.process_cpu_percent
        ):
            raise ValueError("resource measurements must be finite")
        if self.worker_heartbeat_age_seconds is not None and not math.isfinite(
            self.worker_heartbeat_age_seconds
        ):
            raise ValueError("resource measurements must be finite")
        expected_status = "available" if self.sampler_available else "unavailable"
        if self.monitoring_status != expected_status:
            raise ValueError("monitoring status must match sampler availability")
        return self


class RuntimeOutputLedger(CoreSchema):
    ledger_id: UUID = Field(default_factory=uuid4)
    job_id: UUID
    source_id: UUID
    flow_id: UUID
    detection_id: UUID
    alert_id: UUID | None = None
    output_checksum: str
    stage: Literal["detection"] = "detection"
    canonical_input_identity: str = Field(default="", max_length=255)
    output_object_type: Literal["detection_result"] = "detection_result"
    output_object_id: UUID | None = None
    disposition: Literal["created", "reused"] = "created"
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("output_checksum")
    @classmethod
    def validate_checksum(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not _SHA256.fullmatch(normalized):
            raise ValueError("runtime output checksum must be SHA-256")
        return normalized

    @field_validator("created_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return require_aware_utc(value)

    @model_validator(mode="after")
    def populate_explicit_identity(self) -> Self:
        if not self.canonical_input_identity:
            object.__setattr__(self, "canonical_input_identity", str(self.flow_id))
        if self.output_object_id is None:
            object.__setattr__(self, "output_object_id", self.detection_id)
        return self


class RuntimeStatus(CoreSchema):
    queue_length: int = Field(ge=0)
    recovery_pending: int = Field(ge=0)
    running_jobs: int = Field(ge=0)
    paused_jobs: int = Field(ge=0)
    latest_jobs: tuple[RuntimeJob, ...] = ()
    workers: tuple[RuntimeWorker, ...]
    latest_samples: tuple[RuntimeResourceSample, ...]
    latest_errors: tuple[JsonObject, ...]
    model_loading_state: Literal["verified_per_job_preflight"]
    live_capture_enabled: Literal[False]
    automatic_recovery: Literal[False]
