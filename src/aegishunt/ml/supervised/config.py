"""Versioned, bounded supervised experiment configuration."""

from __future__ import annotations

from itertools import product
from pathlib import Path
from typing import Literal, TypeAlias

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from aegishunt.ml.supervised.errors import TrainingError

CONFIG_SCHEMA_VERSION = "1.0.0"
Algorithm = Literal[
    "dummy",
    "logistic_regression",
    "decision_tree",
    "random_forest",
    "hist_gradient_boosting",
]
ParameterValue: TypeAlias = bool | int | float | str | None


class TrainingModel(BaseModel):
    """Strict immutable configuration base."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class CandidateConfig(TrainingModel):
    """One algorithm and its finite parameter grid."""

    algorithm: Algorithm
    parameters: dict[str, tuple[ParameterValue, ...]]

    @model_validator(mode="after")
    def validate_parameters(self) -> CandidateConfig:
        if not self.parameters or any(not values for values in self.parameters.values()):
            raise ValueError("candidate parameter grids must be non-empty")
        combination_count = 1
        for values in self.parameters.values():
            combination_count *= len(values)
        if combination_count > 64:
            raise ValueError("candidate parameter grid exceeds the bounded search limit")
        return self

    def combinations(self) -> tuple[dict[str, ParameterValue], ...]:
        """Expand in stable key/value order for reproducible search."""

        names = tuple(sorted(self.parameters))
        return tuple(
            dict(zip(names, values, strict=True))
            for values in product(*(self.parameters[name] for name in names))
        )


class SupervisedTrainingConfig(TrainingModel):
    """Complete Phase 5 experiment and model-selection policy."""

    config_schema_version: str
    experiment_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    model_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    random_seed: int
    cv_folds: int = Field(ge=2, le=10)
    primary_metric: Literal["macro_f1"]
    calibration_methods: tuple[Literal["sigmoid", "isotonic"], ...]
    min_isotonic_samples_per_class: int = Field(ge=3)
    threshold_candidates: tuple[float, ...]
    latency_repeats: int = Field(ge=10, le=10_000)
    bootstrap_iterations: int = Field(ge=1_000, le=100_000)
    selection_policy_version: str
    candidates: tuple[CandidateConfig, ...]

    @field_validator("threshold_candidates")
    @classmethod
    def validate_thresholds(cls, value: tuple[float, ...]) -> tuple[float, ...]:
        if not value or tuple(sorted(set(value))) != value:
            raise ValueError("threshold candidates must be unique and sorted")
        if value[0] <= 0.0 or value[-1] >= 1.0:
            raise ValueError("threshold candidates must be strictly between zero and one")
        return value

    @model_validator(mode="after")
    def validate_policy(self) -> SupervisedTrainingConfig:
        if self.config_schema_version != CONFIG_SCHEMA_VERSION:
            raise ValueError("unsupported supervised configuration schema")
        algorithms = [candidate.algorithm for candidate in self.candidates]
        required: set[Algorithm] = {
            "dummy",
            "logistic_regression",
            "decision_tree",
            "random_forest",
            "hist_gradient_boosting",
        }
        if set(algorithms) != required or len(algorithms) != len(required):
            raise ValueError("all required supervised candidates must appear exactly once")
        if len(set(self.calibration_methods)) != len(self.calibration_methods):
            raise ValueError("calibration methods must be unique")
        return self

    @classmethod
    def load(cls, path: Path) -> SupervisedTrainingConfig:
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise TrainingError("unable to read supervised training configuration") from exc
        except yaml.YAMLError as exc:
            raise TrainingError("supervised training configuration YAML is invalid") from exc
        try:
            return cls.model_validate(payload)
        except ValidationError as exc:
            errors = exc.errors(include_input=False, include_url=False)
            raise TrainingError(f"supervised training configuration is invalid: {errors}") from exc
