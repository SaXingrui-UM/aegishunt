"""Versioned and bounded Phase 6 experiment configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from aegishunt.ml.anomaly.errors import AnomalyTrainingError

ANOMALY_CONFIG_SCHEMA_VERSION = "1.0.0"
ANOMALY_CORRECTIVE_CONFIG_SCHEMA_VERSION = "1.1.0"
ANOMALY_LOF_CANDIDATE_CONFIG_SCHEMA_VERSION = "2.0.0"
NormalizationStrategy = Literal[
    "benign_training_quantile_cdf",
    "smoothed_empirical_cdf",
    "robust_percentile_scaling",
]


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


def _registered_corrective_forest_matrix() -> tuple[IsolationForestCandidateConfig, ...]:
    """Return the fixed validation-only Isolation Forest comparison matrix."""

    values = (
        ("corrective-iforest-64-full", 64, 1.0, 1.0, False),
        ("corrective-iforest-128-full", 128, 1.0, 1.0, False),
        ("corrective-iforest-256-full", 256, 1.0, 1.0, False),
        ("corrective-iforest-128-sample-80", 128, 0.8, 1.0, False),
        ("corrective-iforest-128-feature-75", 128, 1.0, 0.75, False),
        ("corrective-iforest-128-feature-50", 128, 1.0, 0.5, False),
        (
            "corrective-iforest-128-sample-80-feature-75",
            128,
            0.8,
            0.75,
            False,
        ),
        ("corrective-iforest-128-bootstrap", 128, 1.0, 1.0, True),
    )
    return tuple(
        IsolationForestCandidateConfig(
            candidate_id=candidate_id,
            n_estimators=n_estimators,
            max_samples=max_samples,
            max_features=max_features,
            bootstrap=bootstrap,
            contamination="auto",
            n_jobs=1,
        )
        for candidate_id, n_estimators, max_samples, max_features, bootstrap in values
    )


class LofComparatorConfig(AnomalyConfigModel):
    """Offline novelty-mode LOF comparator policy."""

    enabled: bool = True
    n_neighbors: int = Field(ge=2, le=200)
    metric: str = Field(min_length=1, max_length=64)
    algorithm: Literal["auto", "ball_tree", "kd_tree", "brute"] = "auto"
    leaf_size: int = Field(ge=5, le=200)
    n_jobs: int = Field(ge=1, le=64)


class CorrectiveResearchProtocol(AnomalyConfigModel):
    """Pre-registered evidence boundary for a validation-only corrective search."""

    protocol_version: Literal["1.0.0", "2.0.0"]
    research_type: Literal[
        "validation_only_algorithm_configuration_corrective",
        "validation_only_algorithm_eligibility_promotion",
    ]
    original_experiment_id: str
    original_model_version: str
    dataset_id: str
    dataset_version: str
    dataset_manifest_checksum: str
    split_manifest_checksum: str
    expected_benign_training_rows: Literal[10]
    expected_benign_training_groups: Literal[5]
    expected_validation_rows: Literal[10]
    expected_validation_groups: Literal[5]
    estimator_fit_partition: Literal["benign_training_only"]
    normalizer_fit_partition: Literal["benign_training_only"]
    selection_partition: Literal["validation_only"]
    original_test_access_permitted: Literal[False]
    smoke_fixture_affects_selection: Literal[False]
    lof_production_eligible: bool
    untouched_independent_holdout_required: Literal[True]


class AnomalyTrainingConfig(AnomalyConfigModel):
    """Complete Phase 6 selection and one-time evaluation policy."""

    config_schema_version: str
    experiment_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    model_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:-candidate)?$")
    random_seed: int
    minimum_benign_groups: int = Field(ge=2, le=1_000_000)
    false_positive_rate_limit: float = Field(ge=0.0, lt=1.0)
    threshold_candidates: tuple[float, ...]
    normalization_quantiles: int = Field(ge=5, le=1_001)
    latency_repetitions: int = Field(ge=10, le=10_000)
    bootstrap_iterations: int = Field(ge=1_000, le=100_000)
    selection_policy_version: str
    normalization_version: str
    normalization_strategies: tuple[NormalizationStrategy, ...] = ("benign_training_quantile_cdf",)
    candidate_status: Literal["frozen_test_eligible", "validation_qualified"] = (
        "frozen_test_eligible"
    )
    corrective_protocol: CorrectiveResearchProtocol | None = None
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
        if self.config_schema_version not in {
            ANOMALY_CONFIG_SCHEMA_VERSION,
            ANOMALY_CORRECTIVE_CONFIG_SCHEMA_VERSION,
            ANOMALY_LOF_CANDIDATE_CONFIG_SCHEMA_VERSION,
        }:
            raise ValueError("unsupported anomaly configuration schema")
        identifiers = [item.candidate_id for item in self.isolation_forest_candidates]
        if not identifiers or len(identifiers) != len(set(identifiers)):
            raise ValueError("Isolation Forest candidate IDs must be unique and non-empty")
        if len(self.normalization_strategies) != len(set(self.normalization_strategies)):
            raise ValueError("anomaly normalization strategies must be unique")
        if self.config_schema_version == ANOMALY_CONFIG_SCHEMA_VERSION:
            if (
                self.corrective_protocol is not None
                or self.candidate_status != "frozen_test_eligible"
            ):
                raise ValueError("legacy anomaly configuration cannot declare corrective research")
            if self.normalization_strategies != ("benign_training_quantile_cdf",):
                raise ValueError("legacy anomaly configuration has one fixed normalizer")
        elif self.config_schema_version == ANOMALY_CORRECTIVE_CONFIG_SCHEMA_VERSION:
            if (
                self.corrective_protocol is None
                or self.candidate_status != "validation_qualified"
                or self.selection_policy_version != "1.0.1"
                or self.normalization_version != "1.0.1"
                or not self.model_version.endswith("-candidate")
            ):
                raise ValueError("corrective anomaly protocol is incomplete or inconsistent")
            if len(self.isolation_forest_candidates) != 8:
                raise ValueError("corrective anomaly matrix must contain eight candidates")
            if self.isolation_forest_candidates != _registered_corrective_forest_matrix():
                raise ValueError("corrective anomaly matrix differs from its registration")
            if len(self.normalization_strategies) != 3:
                raise ValueError("corrective anomaly matrix must contain three normalizers")
            if (
                self.corrective_protocol.protocol_version != "1.0.0"
                or self.corrective_protocol.research_type
                != "validation_only_algorithm_configuration_corrective"
                or self.corrective_protocol.lof_production_eligible
            ):
                raise ValueError("corrective anomaly eligibility boundary changed")
        else:
            protocol = self.corrective_protocol
            expected_thresholds = (0.4, 0.5, 0.6, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95)
            expected_normalizers: tuple[NormalizationStrategy, ...] = (
                "benign_training_quantile_cdf",
                "smoothed_empirical_cdf",
                "robust_percentile_scaling",
            )
            expected_lof = LofComparatorConfig(
                enabled=True,
                n_neighbors=5,
                metric="minkowski",
                algorithm="auto",
                leaf_size=30,
                n_jobs=1,
            )
            if (
                protocol is None
                or self.experiment_id != "phase-06-controlled-demo-lof-production-candidate-001"
                or self.candidate_status != "validation_qualified"
                or self.selection_policy_version != "2.0.0"
                or self.normalization_version != "1.0.1"
                or self.model_version != "1.1.0-candidate"
                or self.random_seed != 6106
                or self.false_positive_rate_limit != 0.25
                or self.threshold_candidates != expected_thresholds
                or self.normalization_strategies != expected_normalizers
                or protocol.protocol_version != "2.0.0"
                or protocol.research_type != "validation_only_algorithm_eligibility_promotion"
                or not protocol.lof_production_eligible
                or self.lof != expected_lof
            ):
                raise ValueError("LOF candidate protocol is incomplete or inconsistent")
            if len(self.isolation_forest_candidates) != 8:
                raise ValueError(
                    "LOF candidate protocol must retain eight Isolation Forest candidates"
                )
            if self.isolation_forest_candidates != _registered_corrective_forest_matrix():
                raise ValueError("LOF candidate comparison matrix differs from registration")
            if len(self.normalization_strategies) != 3:
                raise ValueError("LOF candidate protocol must retain three normalizers")
        return self

    @property
    def lof_production_eligible(self) -> bool:
        protocol = self.corrective_protocol
        return bool(protocol is not None and protocol.lof_production_eligible)

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
