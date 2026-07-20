"""Versioned, bounded, pre-registered Phase 7 configuration."""

from __future__ import annotations

import math
from datetime import datetime
from pathlib import Path
from typing import Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from aegishunt.ml.fusion.errors import FusionConfigError
from aegishunt.schemas.base import require_aware_utc

FUSION_CONFIG_SCHEMA_VERSION = "1.0.0"
FUSION_POLICY_VERSION = "1.0.0"


class FusionConfigModel(BaseModel):
    """Strict immutable configuration base."""

    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class WeightCandidate(FusionConfigModel):
    """One true dual-engine weight candidate."""

    candidate_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    supervised_weight: float = Field(gt=0.0, lt=1.0)
    anomaly_weight: float = Field(gt=0.0, lt=1.0)

    @model_validator(mode="after")
    def validate_sum(self) -> Self:
        if not math.isclose(
            self.supervised_weight + self.anomaly_weight,
            1.0,
            rel_tol=0.0,
            abs_tol=1e-12,
        ):
            raise ValueError("fusion candidate weights must sum to one")
        return self


class ParameterShiftDefinition(FusionConfigModel):
    """One bounded feature-space shift fixed before any scoring."""

    shift_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    axis: Literal[
        "flow_duration",
        "packet_rate",
        "packet_size_pattern",
        "connection_frequency",
    ]
    factor: float = Field(gt=1.0, le=2.0)
    description: str = Field(min_length=10, max_length=500)


class FusionExperimentConfig(FusionConfigModel):
    """Complete Phase 7 pre-registration and selection policy."""

    config_schema_version: str
    experiment_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,95}$")
    policy_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,95}$")
    policy_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    dataset_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    dataset_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    feature_schema_version: str
    controlled_synthetic_only: Literal[True]
    public_benchmark: Literal[False]
    groups_per_pattern: int = Field(ge=9, le=30)
    rows_per_group: int = Field(ge=1, le=10)
    data_seed: int
    model_seed: int
    bootstrap_seed: int
    bootstrap_draws: int = Field(ge=1_000, le=100_000)
    protocol_frozen_at: datetime
    supervised_model_id: str
    supervised_model_version: str
    supervised_algorithm: Literal["random_forest"]
    supervised_hyperparameters: dict[str, bool | int | float | str]
    supervised_calibration: Literal["isotonic"]
    supervised_threshold_candidates: tuple[float, ...]
    anomaly_model_id: str
    anomaly_model_version: str
    anomaly_algorithm: Literal["local_outlier_factor"]
    anomaly_hyperparameters: dict[str, bool | int | float | str]
    anomaly_normalization: Literal["benign_training_quantile_cdf"]
    anomaly_threshold_candidates: tuple[float, ...]
    anomaly_false_positive_rate_ceiling: float = Field(ge=0.0, lt=1.0)
    weight_candidates: tuple[WeightCandidate, ...]
    fusion_threshold_candidates: tuple[float, ...]
    false_positive_rate_ceiling: float = Field(ge=0.0, lt=1.0)
    recommendation_min_macro_f1_delta: float = Field(ge=0.0, le=1.0)
    recommendation_max_fpr_increase: float = Field(ge=0.0, le=1.0)
    selection_policy_version: str
    selection_objective: Literal["macro_f1_under_fpr_ceiling"]
    tie_break_order: tuple[str, ...]
    parameter_shifts: tuple[ParameterShiftDefinition, ...]
    latency_repetitions: int = Field(ge=10, le=10_000)
    no_historical_test_access: Literal[True]
    negative_results_retained: Literal[True]

    @field_validator("protocol_frozen_at")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return require_aware_utc(value)

    @field_validator("supervised_threshold_candidates", "fusion_threshold_candidates")
    @classmethod
    def validate_thresholds(cls, value: tuple[float, ...]) -> tuple[float, ...]:
        if not value or tuple(sorted(set(value))) != value:
            raise ValueError("threshold candidates must be sorted and unique")
        if value[0] <= 0.0 or value[-1] >= 1.0:
            raise ValueError("threshold candidates must be strictly inside zero and one")
        return value

    @field_validator("anomaly_threshold_candidates")
    @classmethod
    def validate_anomaly_thresholds(cls, value: tuple[float, ...]) -> tuple[float, ...]:
        if not value or tuple(sorted(set(value))) != value:
            raise ValueError("anomaly thresholds must be sorted and unique")
        if value[0] < 0.0 or value[-1] > 1.0:
            raise ValueError("anomaly thresholds must be inside zero and one")
        return value

    @model_validator(mode="after")
    def validate_protocol(self) -> Self:
        if self.config_schema_version != FUSION_CONFIG_SCHEMA_VERSION:
            raise ValueError("unsupported fusion configuration schema")
        if self.policy_version != FUSION_POLICY_VERSION:
            raise ValueError("unsupported fusion policy version")
        candidate_ids = [item.candidate_id for item in self.weight_candidates]
        if len(candidate_ids) < 2 or len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("fusion weight candidates must contain unique bounded choices")
        axes = [item.axis for item in self.parameter_shifts]
        required_axes = {
            "flow_duration",
            "packet_rate",
            "packet_size_pattern",
            "connection_frequency",
        }
        if set(axes) != required_axes or len(axes) != len(required_axes):
            raise ValueError("all four pre-registered parameter-shift axes are required")
        expected_tie_break = (
            "positive_macro_f1",
            "macro_f1",
            "recall",
            "pr_auc",
            "balanced_accuracy",
            "lower_false_negative_rate",
            "lower_false_positive_rate",
            "stable_candidate_id",
        )
        if self.tie_break_order != expected_tie_break:
            raise ValueError("fusion tie-break order differs from policy 1.0.0")
        expected_supervised = {
            "class_weight": "none",
            "max_depth": 8,
            "max_features": "sqrt",
            "min_samples_leaf": 1,
            "min_samples_split": 2,
            "n_estimators": 64,
            "n_jobs": 1,
        }
        if self.supervised_hyperparameters != expected_supervised:
            raise ValueError("fusion research must retain the corrected Phase 5 configuration")
        expected_anomaly = {
            "n_neighbors": 5,
            "metric": "minkowski",
            "algorithm": "auto",
            "leaf_size": 30,
            "n_jobs": 1,
            "novelty": True,
        }
        if self.anomaly_hyperparameters != expected_anomaly:
            raise ValueError("fusion research must retain the approved Phase 6 LOF configuration")
        return self

    @classmethod
    def load(cls, path: Path) -> FusionExperimentConfig:
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise FusionConfigError("unable to read fusion configuration") from exc
        except yaml.YAMLError as exc:
            raise FusionConfigError("fusion configuration YAML is invalid") from exc
        try:
            return cls.model_validate(payload)
        except ValidationError as exc:
            errors = exc.errors(include_input=False, include_url=False)
            raise FusionConfigError(f"fusion configuration is invalid: {errors}") from exc
