"""Strict checksummed configuration for the single-node Phase 11 runtime."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from aegishunt.datasets.schemas import SHA256_PATTERN
from aegishunt.runtime.errors import RuntimeConfigurationError


class RuntimePolicyModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class ReplayPolicy(RuntimePolicyModel):
    default_speed: float = Field(gt=0.0)
    minimum_speed: float = Field(gt=0.0)
    maximum_speed: float = Field(gt=0.0)
    maximum_sleep_seconds: float = Field(gt=0.0, le=3_600.0)
    sleep_quantum_seconds: float = Field(gt=0.0, le=10.0)

    @model_validator(mode="after")
    def validate_bounds(self) -> Self:
        if not self.minimum_speed <= self.default_speed <= self.maximum_speed:
            raise ValueError("default replay speed must be within configured bounds")
        if self.sleep_quantum_seconds > self.maximum_sleep_seconds:
            raise ValueError("sleep quantum cannot exceed the maximum replay sleep")
        return self


class WorkerPolicy(RuntimePolicyModel):
    poll_interval_seconds: float = Field(gt=0.0, le=60.0)
    lease_seconds: float = Field(gt=0.0, le=3_600.0)
    heartbeat_interval_seconds: float = Field(gt=0.0, le=600.0)
    stale_after_seconds: float = Field(gt=0.0, le=7_200.0)
    maximum_attempts: int = Field(ge=1, le=100)
    persistence_batch_size: int = Field(ge=1, le=10_000)
    progress_update_packet_interval: int = Field(ge=1, le=1_000_000)
    progress_update_seconds: float = Field(gt=0.0, le=600.0)
    correlation_alert_batch_size: int = Field(ge=1, le=100_000)
    maximum_jobs_per_query: int = Field(ge=1, le=1_000)
    maximum_workers_per_query: int = Field(ge=1, le=1_000)

    @model_validator(mode="after")
    def validate_timing(self) -> Self:
        if self.heartbeat_interval_seconds >= self.lease_seconds:
            raise ValueError("worker heartbeat must be shorter than its lease")
        if self.stale_after_seconds <= self.lease_seconds:
            raise ValueError("stale threshold must be longer than the lease")
        return self


class ResourcePolicy(RuntimePolicyModel):
    sample_interval_seconds: float = Field(gt=0.0, le=600.0)
    retention_samples_per_worker: int = Field(ge=1, le=100_000)


class RuntimePolicy(RuntimePolicyModel):
    policy_schema_version: Literal["1.0.0"]
    policy_id: str = Field(min_length=1, max_length=255)
    policy_version: str = Field(min_length=1, max_length=64)
    job_schema_version: Literal["1.0.0"]
    attempt_schema_version: Literal["1.0.0"]
    worker_schema_version: Literal["1.0.0"]
    resource_sample_schema_version: Literal["1.0.0"]
    supervised_model_version: str = Field(min_length=1, max_length=128)
    anomaly_model_version: str = Field(min_length=1, max_length=128)
    fusion_policy_version: str = Field(min_length=1, max_length=128)
    explanation_artifact_version: str = Field(min_length=1, max_length=128)
    feature_schema_version: str = Field(min_length=1, max_length=64)
    replay: ReplayPolicy
    worker: WorkerPolicy
    resources: ResourcePolicy
    pipeline_stages: tuple[
        Literal[
            "preflight",
            "replay",
            "detection",
            "correlation",
            "hypothesis",
            "completion",
        ],
        ...,
    ] = Field(min_length=6, max_length=6)
    output_identity_policy: Literal[
        "deterministic_domain_ids_with_verified_runtime_ledger"
    ]
    retryable_error_categories: tuple[
        Literal["database_temporarily_unavailable", "worker_interrupted"],
        ...,
    ] = Field(min_length=2, max_length=2)
    runtime_policy_semantics: Literal[
        "offline_event_time_replay_with_explicit_origin_recovery"
    ]
    automatic_recovery: Literal[False]
    live_capture_enabled: Literal[False]
    recovery_strategy: Literal["deterministic_restart_from_origin"]
    execution_mode: Literal["single_node_sqlite"]

    @model_validator(mode="after")
    def validate_pipeline_contract(self) -> Self:
        if self.pipeline_stages != (
            "preflight",
            "replay",
            "detection",
            "correlation",
            "hypothesis",
            "completion",
        ):
            raise ValueError("runtime pipeline stages must use the fixed audited order")
        if len(set(self.retryable_error_categories)) != len(
            self.retryable_error_categories
        ):
            raise ValueError("runtime retryable error categories must be unique")
        return self


class LoadedRuntimePolicy(RuntimePolicyModel):
    policy: RuntimePolicy
    configuration_checksum: str

    @model_validator(mode="after")
    def validate_checksum(self) -> Self:
        if not SHA256_PATTERN.fullmatch(self.configuration_checksum):
            raise ValueError("runtime policy checksum must be SHA-256")
        return self


def load_runtime_policy(path: Path) -> LoadedRuntimePolicy:
    """Load one regular YAML policy and bind the exact bytes to its identity."""

    if not path.is_file() or path.is_symlink():
        raise RuntimeConfigurationError("runtime policy must be a regular file")
    try:
        payload = path.read_bytes()
        raw = yaml.safe_load(payload)
        if not isinstance(raw, dict):
            raise RuntimeConfigurationError("runtime policy root must be a mapping")
        policy = RuntimePolicy.model_validate(raw)
    except RuntimeConfigurationError:
        raise
    except (OSError, ValidationError, yaml.YAMLError) as exc:
        raise RuntimeConfigurationError("runtime policy is invalid") from exc
    return LoadedRuntimePolicy(
        policy=policy,
        configuration_checksum=hashlib.sha256(payload).hexdigest(),
    )
