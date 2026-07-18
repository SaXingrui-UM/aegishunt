"""Versioned and bounded Phase 6 experiment configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from aegishunt.ml.anomaly.errors import AnomalyTrainingError

ANOMALY_CONFIG_SCHEMA_VERSION = "1.0.0"


class AnomalyConfigModel(BaseModel):
    """Strict immutable base for anomaly configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class IsolationForestCandidateConfig(AnomalyConfigModel):
    """One explicitly bounded production-candidate configuration."""

    candidate_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    n_estimators: int = Field(ge=16, le=2_048)
    max_samples: float = Field(gt=0.0, le=1.0)
    max_features: float = Field(gt=0.0, le=1.0)
    bootstrap: bool
    contamination: Literal["auto"]
    n_jobs: int = Field(ge=1, le=64)


class LofComparatorConfig(AnomalyConfigModel):
    """Offline novelty-mode LOF comparator policy."""

    enabled: bool = True
    n_neighbors: int = Field(ge=2, le=200)
    metric: str = Field(min_length=1, max_length=64)
    algorithm: Literal["auto", "ball_tree", "kd_tree", "brute"] = "auto"
    leaf_size: int = Field(ge=5, le=200)
    n_jobs: int = Field(ge=1, le=64)


class AnomalyTrainingConfig(AnomalyConfigModel):
    """Complete Phase 6 selection and one-time evaluation policy."""

    config_schema_version: str
    experiment_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    model_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    random_seed: int
    minimum_benign_groups: int = Field(ge=2, le=1_000_000)
    false_positive_rate_limit: float = Field(ge=0.0, lt=1.0)
    threshold_candidates: tuple[float, ...]
    normalization_quantiles: int = Field(ge=5, le=1_001)
    latency_repetitions: int = Field(ge=10, le=10_000)
    bootstrap_iterations: int = Field(ge=1_000, le=100_000)
    selection_policy_version: str
    normalization_version: str
    isolation_forest_candidates: tuple[IsolationForestCandidateConfig, ...]
    lof: LofComparatorConfig
    one_class_svm_status: Literal["not_implemented"]
    one_class_svm_reason: str = Field(min_length=20, max_length=500)

    @field_validator("threshold_candidates")
    @classmethod
    def validate_thresholds(cls, value: tuple[float, ...]) -> tuple[float, ...]:
        if not value or value != tuple(sorted(set(value))):
            raise ValueError("anomaly thresholds must be unique and sorted")
        if value[0] < 0.0 or value[-1] > 1.0:
            raise ValueError("anomaly thresholds must be within zero and one")
        return value

    @model_validator(mode="after")
    def validate_policy(self) -> AnomalyTrainingConfig:
        if self.config_schema_version != ANOMALY_CONFIG_SCHEMA_VERSION:
            raise ValueError("unsupported anomaly configuration schema")
        identifiers = [item.candidate_id for item in self.isolation_forest_candidates]
        if not identifiers or len(identifiers) != len(set(identifiers)):
            raise ValueError("Isolation Forest candidate IDs must be unique and non-empty")
        return self

    @classmethod
    def load(cls, path: Path) -> AnomalyTrainingConfig:
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise AnomalyTrainingError("unable to read anomaly training configuration") from exc
        except yaml.YAMLError as exc:
            raise AnomalyTrainingError("anomaly training configuration YAML is invalid") from exc
        try:
            return cls.model_validate(payload)
        except ValidationError as exc:
            errors = exc.errors(include_input=False, include_url=False)
            raise AnomalyTrainingError(
                f"anomaly training configuration is invalid: {errors}"
            ) from exc
