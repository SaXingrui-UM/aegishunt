"""Serializable Phase 6 selection, evaluation, and bundle contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aegishunt.datasets.schemas import SHA256_PATTERN
from aegishunt.schemas.base import require_aware_utc

ANOMALY_CONTRACT_VERSION = "1.0.0"
AnomalyAlgorithm = Literal["isolation_forest", "local_outlier_factor"]


class AnomalyModel(BaseModel):
    """Strict immutable base for auditable anomaly evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class AnomalyClassMetrics(AnomalyModel):
    precision: float = Field(ge=0.0, le=1.0)
    recall: float = Field(ge=0.0, le=1.0)
    f1: float = Field(ge=0.0, le=1.0)
    support: int = Field(ge=0)


class AnomalyMetrics(AnomalyModel):
    """Binary metrics where malicious/anomaly is always the positive class."""

    accuracy: float = Field(ge=0.0, le=1.0)
    precision: float = Field(ge=0.0, le=1.0)
    recall: float = Field(ge=0.0, le=1.0)
    f1: float = Field(ge=0.0, le=1.0)
    macro_f1: float = Field(ge=0.0, le=1.0)
    weighted_f1: float = Field(ge=0.0, le=1.0)
    balanced_accuracy: float = Field(ge=0.0, le=1.0)
    mcc: float = Field(ge=-1.0, le=1.0)
    roc_auc: float | None = Field(default=None, ge=0.0, le=1.0)
    pr_auc: float | None = Field(default=None, ge=0.0, le=1.0)
    specificity: float = Field(ge=0.0, le=1.0)
    benign_false_positive_rate: float = Field(ge=0.0, le=1.0)
    anomaly_false_negative_rate: float = Field(ge=0.0, le=1.0)
    confusion_matrix: tuple[tuple[int, int], tuple[int, int]]
    per_class: dict[str, AnomalyClassMetrics]
    unavailable_metrics: tuple[str, ...] = ()


class ScoreDistribution(AnomalyModel):
    count: int = Field(ge=1)
    minimum: float
    q05: float
    q25: float
    median: float
    q75: float
    q95: float
    maximum: float
    mean: float
    standard_deviation: float = Field(ge=0.0)


class GroupStability(AnomalyModel):
    group_count: int = Field(ge=1)
    benign_fpr_mean: float = Field(ge=0.0, le=1.0)
    benign_fpr_standard_deviation: float = Field(ge=0.0)
    anomaly_recall_mean: float = Field(ge=0.0, le=1.0)
    anomaly_recall_standard_deviation: float = Field(ge=0.0)
    groups_without_benign: int = Field(ge=0)
    groups_without_anomaly: int = Field(ge=0)


class ScoreNormalization(AnomalyModel):
    version: str
    method: Literal[
        "benign_training_quantile_cdf",
        "smoothed_empirical_cdf",
        "robust_percentile_scaling",
    ]
    score_direction: Literal["higher_is_more_anomalous"]
    reference_partition: Literal["benign_training"]
    canonical_score_knots: tuple[float, ...]
    normalized_score_knots: tuple[float, ...]
    clipping: Literal["clip_to_unit_interval"]
    constant_score_value: float = Field(default=0.5, ge=0.0, le=1.0)


class ThresholdResult(AnomalyModel):
    threshold: float = Field(ge=0.0, le=1.0)
    metrics: AnomalyMetrics
    group_stability: GroupStability
    satisfies_fpr_limit: bool


class AnomalyOperationalMetrics(AnomalyModel):
    training_duration_seconds: float = Field(ge=0.0)
    batch_size: int = Field(ge=1)
    repetitions: int = Field(ge=1)
    batch_latency_p50_ms: float = Field(ge=0.0)
    batch_latency_p95_ms: float = Field(ge=0.0)
    batch_latency_p99_ms: float = Field(ge=0.0)
    per_sample_latency_p50_ms: float = Field(ge=0.0)
    throughput_samples_per_second: float = Field(ge=0.0)
    estimator_serialized_size_bytes: int = Field(ge=1)
    deterministic_scores: bool
    peak_memory_bytes: int | None = Field(default=None, ge=0)


class AnomalyCandidateResult(AnomalyModel):
    candidate_id: str
    algorithm: AnomalyAlgorithm
    hyperparameters: dict[str, bool | int | float | str]
    normalization_strategy: str = "benign_training_quantile_cdf"
    status: Literal["passed", "failed"]
    failure_code: str | None = None
    benign_training_rows: int = Field(ge=1)
    benign_training_groups: int = Field(ge=1)
    validation_rows: int = Field(ge=1)
    validation_groups: int = Field(ge=1)
    selected_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    threshold_results: tuple[ThresholdResult, ...] = ()
    validation_metrics: AnomalyMetrics | None = None
    normalizer: ScoreNormalization | None = None
    benign_raw_distribution: ScoreDistribution | None = None
    anomaly_raw_distribution: ScoreDistribution | None = None
    benign_normalized_distribution: ScoreDistribution | None = None
    anomaly_normalized_distribution: ScoreDistribution | None = None
    operational_metrics: AnomalyOperationalMetrics | None = None


# Backward-compatible name retained for the original Phase 6 evidence readers.
IsolationForestCandidateResult = AnomalyCandidateResult


class ComparatorResult(AnomalyModel):
    algorithm: Literal["local_outlier_factor", "one_class_svm"]
    candidate_id: str | None = None
    production_eligible: bool
    status: Literal["passed", "failed", "not_implemented"]
    hyperparameters: dict[str, bool | int | float | str]
    preprocessing: Literal["standard_scaler"] | None = None
    raw_score_method: Literal["score_samples"] | None = None
    canonical_score_transform: Literal["negative_raw_score"] | None = None
    normalizer: ScoreNormalization | None = None
    threshold_policy: Literal["validation_benign_fpr_constrained"] | None = None
    false_positive_rate_limit: float | None = Field(default=None, ge=0.0, lt=1.0)
    benign_training_rows: int | None = Field(default=None, ge=1)
    benign_training_groups: int | None = Field(default=None, ge=1)
    validation_rows: int | None = Field(default=None, ge=1)
    validation_groups: int | None = Field(default=None, ge=1)
    selected_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    threshold_results: tuple[ThresholdResult, ...] = ()
    validation_metrics: AnomalyMetrics | None = None
    benign_raw_distribution: ScoreDistribution | None = None
    anomaly_raw_distribution: ScoreDistribution | None = None
    benign_normalized_distribution: ScoreDistribution | None = None
    anomaly_normalized_distribution: ScoreDistribution | None = None
    operational_metrics: AnomalyOperationalMetrics | None = None
    limitations: tuple[str, ...]
    failure_code: str | None = None


class BenignTrainingManifest(AnomalyModel):
    dataset_id: str
    dataset_version: str
    partition: Literal["train"]
    benign_rows: int = Field(ge=1)
    benign_groups: tuple[str, ...]
    benign_row_identity_digest: str
    excluded_malicious_rows: int = Field(ge=0)
    validation_rows: int = Field(ge=1)
    validation_groups: tuple[str, ...]
    labels_used_for_fit: tuple[Literal[0], ...] = (0,)
    metadata_used_as_features: Literal[False]
    test_data_accessed: Literal[False]

    @field_validator("benign_row_identity_digest")
    @classmethod
    def validate_identity_digest(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("benign row identity digest must be SHA-256")
        return normalized


class AnomalySelectionRecord(AnomalyModel):
    record_schema_version: str
    status: Literal["frozen", "validation_qualified"]
    experiment_id: str
    model_id: str
    model_version: str
    algorithm: AnomalyAlgorithm
    selected_candidate_id: str
    hyperparameters: dict[str, bool | int | float | str]
    preprocessing: Literal["standard_scaler"]
    raw_score_method: Literal["score_samples"]
    canonical_score_transform: Literal["negative_raw_score"]
    normalizer: ScoreNormalization
    threshold: float = Field(ge=0.0, le=1.0)
    threshold_policy: Literal["validation_benign_fpr_constrained"]
    false_positive_rate_limit: float = Field(ge=0.0, lt=1.0)
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
    benign_training_rows: int = Field(ge=1)
    benign_training_groups: tuple[str, ...]
    benign_training_identity_digest: str
    validation_rows: int = Field(ge=1)
    validation_groups: tuple[str, ...]
    random_seed: int
    training_config_checksum: str
    selection_artifact_filename: Literal["selection.skops"]
    selection_artifact_checksum: str
    trusted_types: tuple[str, ...]
    validation_metrics: AnomalyMetrics
    group_stability: GroupStability
    operational_metrics: AnomalyOperationalMetrics
    lof_comparison: ComparatorResult
    one_class_svm_comparison: ComparatorResult
    pipeline_verification_only: bool
    test_data_accessed: Literal[False]
    created_at: datetime

    @field_validator(
        "dataset_manifest_checksum",
        "split_manifest_checksum",
        "training_config_checksum",
        "selection_artifact_checksum",
        "benign_training_identity_digest",
    )
    @classmethod
    def validate_checksum(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("anomaly selection checksum must be SHA-256")
        return normalized

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return require_aware_utc(value)


class ConfidenceInterval(AnomalyModel):
    lower: float
    upper: float
    confidence_level: float = 0.95
    successful_iterations: int = Field(ge=1)


class AnomalyFrozenTestReport(AnomalyModel):
    report_schema_version: str
    experiment_id: str
    model_id: str
    model_version: str
    selection_record_checksum: str
    evaluation_count: Literal[1]
    metrics: AnomalyMetrics
    confidence_intervals: dict[str, ConfidenceInterval]
    benign_raw_distribution: ScoreDistribution
    anomaly_raw_distribution: ScoreDistribution
    benign_normalized_distribution: ScoreDistribution
    anomaly_normalized_distribution: ScoreDistribution
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
            raise ValueError("anomaly selection-record checksum must be SHA-256")
        return normalized

    @field_validator("evaluated_at")
    @classmethod
    def validate_evaluated_at(cls, value: datetime) -> datetime:
        return require_aware_utc(value)


class AnomalyPredictionResult(AnomalyModel):
    raw_model_score: float
    canonical_anomaly_score: float
    normalized_anomaly_score: float = Field(ge=0.0, le=1.0)
    selected_threshold: float = Field(ge=0.0, le=1.0)
    is_anomaly: bool
    model_id: str
    model_version: str
    feature_schema_version: str
    scored_at: datetime

    @field_validator("scored_at")
    @classmethod
    def validate_scored_at(cls, value: datetime) -> datetime:
        return require_aware_utc(value)


class CandidateSmokeResult(AnomalyModel):
    result_schema_version: Literal["1.0.0"]
    fixture_id: Literal["phase-06-fixed-syn-burst-v1"]
    fixture_checksum: str
    affected_selection: Literal[False]
    ran_after_selection_freeze: Literal[True]
    independently_reloaded: bool
    prediction: AnomalyPredictionResult
    passed: bool
    evaluated_at: datetime

    @field_validator("fixture_checksum")
    @classmethod
    def validate_fixture_checksum(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("candidate smoke fixture checksum must be SHA-256")
        return normalized

    @field_validator("evaluated_at")
    @classmethod
    def validate_smoke_timestamp(cls, value: datetime) -> datetime:
        return require_aware_utc(value)


class AnomalyBundleManifest(AnomalyModel):
    manifest_schema_version: str
    model_id: str
    model_version: str
    model_type: Literal["anomaly"]
    algorithm: AnomalyAlgorithm
    artifact_filename: Literal["model.skops"]
    artifact_checksum: str
    trusted_types: tuple[str, ...]
    preprocessing: Literal["standard_scaler"]
    raw_score_method: Literal["score_samples"]
    canonical_score_transform: Literal["negative_raw_score"]
    normalizer: ScoreNormalization
    anomaly_threshold: float = Field(ge=0.0, le=1.0)
    threshold_policy: Literal["validation_benign_fpr_constrained"]
    false_positive_rate_limit: float = Field(ge=0.0, lt=1.0)
    feature_names: tuple[str, ...]
    feature_schema_version: str
    expected_dtype: Literal["float64"]
    training_dataset_id: str
    training_dataset_version: str
    dataset_manifest_checksum: str
    split_manifest_checksum: str
    label_mapping_version: str
    training_config_checksum: str
    benign_training_rows: int = Field(ge=1)
    benign_training_groups: tuple[str, ...]
    benign_training_identity_digest: str
    random_seed: int
    hyperparameters: dict[str, bool | int | float | str]
    validation_metrics: AnomalyMetrics
    frozen_test_metrics: AnomalyMetrics | None
    operational_metrics: AnomalyOperationalMetrics
    pipeline_verification_only: bool
    python_version: str
    sklearn_version: str
    git_commit_sha: str | None
    status: Literal["validated", "validation_qualified"]
    candidate_smoke_fixture_checksum: str | None = None
    candidate_smoke_test_passed: bool | None = None
    untouched_independent_holdout_available: bool | None = None
    created_at: datetime

    @field_validator(
        "artifact_checksum",
        "dataset_manifest_checksum",
        "split_manifest_checksum",
        "training_config_checksum",
        "benign_training_identity_digest",
        "candidate_smoke_fixture_checksum",
    )
    @classmethod
    def validate_bundle_checksum(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        if not SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("anomaly bundle checksum must be SHA-256")
        return normalized

    @field_validator("created_at")
    @classmethod
    def validate_bundle_timestamp(cls, value: datetime) -> datetime:
        return require_aware_utc(value)


class AnomalyBundleChecksums(AnomalyModel):
    checksum_schema_version: Literal["1.0.0"]
    model_checksum: str
    manifest_checksum: str
    model_card_checksum: str

    @field_validator("model_checksum", "manifest_checksum", "model_card_checksum")
    @classmethod
    def validate_file_checksum(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("anomaly bundle file checksum must be SHA-256")
        return normalized
