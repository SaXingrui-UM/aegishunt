"""Versioned, bounded supervised experiment configuration."""

from __future__ import annotations

from itertools import product
from pathlib import Path
from typing import Literal, TypeAlias

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from aegishunt.ml.supervised.errors import TrainingError

CONFIG_SCHEMA_VERSION = "1.0.0"
CORRECTIVE_CONFIG_SCHEMA_VERSION = "1.1.0"
PORTABLE_DEMO_SELECTION_POLICY_VERSION = "phase12-portable-demo-1.0.0"
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


class CorrectiveRunConfig(TrainingModel):
    """Explicit audit link for a defect-authorized evidence rerun."""

    defect_id: str = Field(pattern=r"^[A-Z][A-Z0-9-]{2,63}$")
    supersedes_experiment_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    supersedes_model_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    reason: str = Field(min_length=10, max_length=500)


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
    corrective_run: CorrectiveRunConfig | None = None

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
        supported_versions = {CONFIG_SCHEMA_VERSION, CORRECTIVE_CONFIG_SCHEMA_VERSION}
        if self.config_schema_version not in supported_versions:
            raise ValueError("unsupported supervised configuration schema")
        if self.corrective_run is None and self.config_schema_version != CONFIG_SCHEMA_VERSION:
            raise ValueError("corrective configuration schema requires corrective-run metadata")
        if self.corrective_run is not None:
            if self.config_schema_version != CORRECTIVE_CONFIG_SCHEMA_VERSION:
                raise ValueError("corrective runs require configuration schema 1.1.0")
            if self.experiment_id == self.corrective_run.supersedes_experiment_id:
                raise ValueError("corrective run must use a new experiment ID")
            if self.model_version == self.corrective_run.supersedes_model_version:
                raise ValueError("corrective run must use a new model version")
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
