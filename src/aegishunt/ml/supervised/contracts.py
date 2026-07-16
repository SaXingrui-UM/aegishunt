"""Serializable Phase 5 experiment, selection, and bundle contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aegishunt.datasets.schemas import SHA256_PATTERN
from aegishunt.schemas.base import require_aware_utc

SUPERVISED_CONTRACT_VERSION = "1.0.0"


class SupervisedModel(BaseModel):
    """Strict immutable base for auditable experiment evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class PerClassMetrics(SupervisedModel):
    precision: float
    recall: float
    f1: float
    support: int = Field(ge=0)


class ClassificationMetrics(SupervisedModel):
    accuracy: float
    precision: float
    recall: float
    f1: float
    macro_f1: float
    weighted_f1: float
    balanced_accuracy: float
    mcc: float
    roc_auc: float | None
    pr_auc: float | None
    specificity: float
    false_positive_rate: float
    false_negative_rate: float
    brier_score: float | None
    confusion_matrix: tuple[tuple[int, int], tuple[int, int]]
    per_class: dict[str, PerClassMetrics]
    unavailable_metrics: tuple[str, ...] = ()


class FoldEvidence(SupervisedModel):
    fold_index: int = Field(ge=0)
    train_groups: tuple[str, ...]
    validation_groups: tuple[str, ...]
    train_rows: int = Field(ge=1)
    validation_rows: int = Field(ge=1)
    train_class_distribution: dict[str, int]
    validation_class_distribution: dict[str, int]
    group_overlap: tuple[str, ...] = ()
    source_overlap: tuple[str, ...] = ()
    session_overlap: tuple[str, ...] = ()
    scenario_overlap: tuple[str, ...] = ()


class FoldResult(SupervisedModel):
    evidence: FoldEvidence
    metrics: ClassificationMetrics


class HyperparameterResult(SupervisedModel):
    algorithm: str
    parameters: dict[str, bool | int | float | str | None]
    status: Literal["passed", "failed"]
    failure_code: str | None = None
    folds: tuple[FoldResult, ...] = ()
    mean_metrics: dict[str, float | None] = Field(default_factory=dict)
    std_metrics: dict[str, float | None] = Field(default_factory=dict)
    training_duration_seconds: float = Field(ge=0.0)


class CalibrationResult(SupervisedModel):
    method: Literal["sigmoid", "isotonic"]
    status: Literal["passed", "not_applicable", "failed"]
    brier_score: float | None = None
    failure_code: str | None = None


class ThresholdResult(SupervisedModel):
    threshold: float = Field(gt=0.0, lt=1.0)
    metrics: ClassificationMetrics


class OperationalMetrics(SupervisedModel):
    training_duration_seconds: float = Field(ge=0.0)
    batch_size: int = Field(ge=1)
    repetitions: int = Field(ge=1)
    batch_latency_p50_ms: float = Field(ge=0.0)
    batch_latency_p95_ms: float = Field(ge=0.0)
    batch_latency_p99_ms: float = Field(ge=0.0)
    per_sample_latency_p50_ms: float = Field(ge=0.0)
    throughput_samples_per_second: float = Field(ge=0.0)
    serialized_size_bytes: int = Field(ge=1)
    deterministic_predictions: bool
    peak_memory_bytes: int | None = None


class CandidateValidationResult(SupervisedModel):
    algorithm: str
    hyperparameters: dict[str, bool | int | float | str | None]
    calibration_method: Literal["sigmoid", "isotonic"]
    calibration_candidates: tuple[CalibrationResult, ...]
    threshold: float = Field(gt=0.0, lt=1.0)
    threshold_results: tuple[ThresholdResult, ...]
    validation_metrics: ClassificationMetrics
    cv_mean_metrics: dict[str, float | None]
    cv_std_metrics: dict[str, float | None]
    operational_metrics: OperationalMetrics


class ModelSelectionRecord(SupervisedModel):
    record_schema_version: str
    status: Literal["frozen"]
    experiment_id: str
    model_id: str
    model_version: str
    algorithm: str
    hyperparameters: dict[str, bool | int | float | str | None]
    preprocessing_version: str
    calibration_method: Literal["sigmoid", "isotonic"]
    threshold: float = Field(gt=0.0, lt=1.0)
    selection_policy_version: str
    selection_rationale: tuple[str, ...]
    dataset_id: str
    dataset_version: str
    dataset_manifest_checksum: str
    split_manifest_checksum: str
    feature_schema_version: str
    feature_names: tuple[str, ...]
    expected_dtype: Literal["float64"]
    label_mapping_version: str
    random_seed: int
    training_config_checksum: str
    selection_artifact_filename: Literal["selection.skops"]
    selection_artifact_checksum: str
    trusted_types: tuple[str, ...]
    validation_metrics: ClassificationMetrics
    cv_mean_metrics: dict[str, float | None]
    cv_std_metrics: dict[str, float | None]
    operational_metrics: OperationalMetrics
    pipeline_verification_only: bool
    test_data_accessed: Literal[False]
    created_at: datetime

    @field_validator(
        "dataset_manifest_checksum",
        "split_manifest_checksum",
        "training_config_checksum",
        "selection_artifact_checksum",
    )
    @classmethod
    def validate_checksum(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("selection checksum must be SHA-256")
        return normalized

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return require_aware_utc(value)


class ConfidenceInterval(SupervisedModel):
    lower: float
    upper: float
    confidence_level: float = 0.95
    successful_iterations: int = Field(ge=1)


class FrozenTestReport(SupervisedModel):
    report_schema_version: str
    experiment_id: str
    model_id: str
    model_version: str
    selection_record_checksum: str
    evaluation_count: Literal[1]
    metrics: ClassificationMetrics
    confidence_intervals: dict[str, ConfidenceInterval]
    row_count: int = Field(ge=1)
    group_count: int = Field(ge=1)
    class_distribution: dict[str, int]
    test_affected_selection: Literal[False]
    pipeline_verification_only: bool
    evaluated_at: datetime

    @field_validator("selection_record_checksum")
    @classmethod
    def validate_selection_checksum(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("selection record checksum must be SHA-256")
        return normalized

    @field_validator("evaluated_at")
    @classmethod
    def validate_evaluated_at(cls, value: datetime) -> datetime:
        return require_aware_utc(value)


class PredictionResult(SupervisedModel):
    predicted_label: Literal[0, 1]
    raw_score: float
    calibrated_probability: float = Field(ge=0.0, le=1.0)
    selected_threshold: float = Field(gt=0.0, lt=1.0)
    model_id: str
    model_version: str
    feature_schema_version: str
    prediction_timestamp: datetime

    @field_validator("prediction_timestamp")
    @classmethod
    def validate_prediction_timestamp(cls, value: datetime) -> datetime:
        return require_aware_utc(value)


class BundleManifest(SupervisedModel):
    manifest_schema_version: str
    model_id: str
    model_version: str
    model_type: Literal["supervised"]
    algorithm: str
    artifact_filename: Literal["model.skops"]
    artifact_checksum: str
    trusted_types: tuple[str, ...]
    preprocessing_version: str
    calibration_method: Literal["sigmoid", "isotonic"]
    classification_threshold: float = Field(gt=0.0, lt=1.0)
    feature_names: tuple[str, ...]
    feature_schema_version: str
    expected_dtype: Literal["float64"]
    training_dataset_id: str
    training_dataset_version: str
    dataset_manifest_checksum: str
    split_manifest_checksum: str
    label_mapping_version: str
    training_config_checksum: str
    random_seed: int
    hyperparameters: dict[str, bool | int | float | str | None]
    validation_metrics: ClassificationMetrics
    frozen_test_metrics: ClassificationMetrics | None
    pipeline_verification_only: bool
    python_version: str
    sklearn_version: str
    git_commit_sha: str | None
    status: Literal["validated"]
    created_at: datetime

    @field_validator(
        "artifact_checksum",
        "dataset_manifest_checksum",
        "split_manifest_checksum",
        "training_config_checksum",
    )
    @classmethod
    def validate_manifest_checksum(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("bundle checksum must be SHA-256")
        return normalized

    @field_validator("created_at")
    @classmethod
    def validate_bundle_timestamp(cls, value: datetime) -> datetime:
        return require_aware_utc(value)


class BundleChecksums(SupervisedModel):
    """Outer integrity inventory for every file that defines one bundle."""

    checksum_schema_version: Literal["1.0.0"]
    model_checksum: str
    manifest_checksum: str
    model_card_checksum: str

    @field_validator("model_checksum", "manifest_checksum", "model_card_checksum")
    @classmethod
    def validate_bundle_file_checksum(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("bundle file checksum must be SHA-256")
        return normalized
