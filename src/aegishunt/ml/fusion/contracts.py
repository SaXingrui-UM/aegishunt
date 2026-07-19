"""Strict serializable contracts for fusion scoring and evidence."""

from __future__ import annotations

import math
from datetime import datetime
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegishunt.datasets.schemas import SHA256_PATTERN
from aegishunt.ml.anomaly.contracts import AnomalyMetrics
from aegishunt.schemas.base import require_aware_utc

FUSION_CONTRACT_VERSION = "1.0.0"
EvaluationMode = Literal["supervised_only", "anomaly_only", "dual_engine_fusion"]
RecommendationStatus = Literal[
    "fusion_recommended",
    "fusion_not_recommended",
    "inconclusive",
]


class FusionModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class FusionWeights(FusionModel):
    supervised_weight: float = Field(ge=0.0, le=1.0)
    anomaly_weight: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def validate_sum(self) -> Self:
        if not math.isclose(
            self.supervised_weight + self.anomaly_weight,
            1.0,
            rel_tol=0.0,
            abs_tol=1e-12,
        ):
            raise ValueError("fusion weights must sum to one")
        return self

    @property
    def is_dual_engine(self) -> bool:
        return self.supervised_weight > 0.0 and self.anomaly_weight > 0.0


class FusionScoreInput(FusionModel):
    supervised_probability: float = Field(ge=0.0, le=1.0)
    normalized_anomaly_score: float = Field(ge=0.0, le=1.0)
    supervised_model_id: str
    supervised_model_version: str
    anomaly_model_id: str
    anomaly_model_version: str
    feature_schema_version: str


class FusionScoreResult(FusionModel):
    supervised_probability: float = Field(ge=0.0, le=1.0)
    normalized_anomaly_score: float = Field(ge=0.0, le=1.0)
    supervised_weight: float = Field(gt=0.0, lt=1.0)
    anomaly_weight: float = Field(gt=0.0, lt=1.0)
    fusion_score: float = Field(ge=0.0, le=1.0)
    selected_fusion_threshold: float = Field(gt=0.0, lt=1.0)
    fusion_positive: bool
    policy_id: str
    policy_version: str
    scored_at: datetime
    semantics: Literal[
        "experimental suspiciousness score; not probability, risk, severity, or attack confirmation"
    ]

    @field_validator("scored_at")
    @classmethod
    def validate_scored_at(cls, value: datetime) -> datetime:
        return require_aware_utc(value)


class CandidateEvaluation(FusionModel):
    candidate_id: str
    mode: EvaluationMode
    weights: FusionWeights | None
    threshold: float = Field(ge=0.0, le=1.0)
    metrics: AnomalyMetrics
    satisfies_fpr_ceiling: bool
    selection_used_validation_only: Literal[True]

    @model_validator(mode="after")
    def validate_mode(self) -> Self:
        if self.mode == "dual_engine_fusion":
            if self.weights is None or not self.weights.is_dual_engine:
                raise ValueError("dual-engine evidence requires two positive weights")
        elif self.weights is not None:
            raise ValueError("baseline evidence cannot masquerade as weighted fusion")
        if self.mode != "anomaly_only" and not 0.0 < self.threshold < 1.0:
            raise ValueError("supervised and fusion thresholds must be inside zero and one")
        return self


class MetricInterval(FusionModel):
    lower: float | None = None
    upper: float | None = None
    confidence_level: float = Field(default=0.95, ge=0.95, le=0.95)
    requested_draws: int = Field(ge=1_000)
    successful_draws: int = Field(ge=0)
    unavailable_reason: str | None = None

    @model_validator(mode="after")
    def validate_availability(self) -> Self:
        bounds_present = self.lower is not None and self.upper is not None
        if bounds_present != (self.unavailable_reason is None):
            raise ValueError("confidence interval availability is inconsistent")
        if (
            bounds_present
            and self.lower is not None
            and self.upper is not None
            and (self.lower > self.upper or self.successful_draws == 0)
        ):
            raise ValueError("confidence interval bounds are invalid")
        return self


class FusionSelectionRecord(FusionModel):
    record_schema_version: Literal["1.0.0"]
    status: Literal["validation_frozen"]
    experiment_id: str
    policy_id: str
    policy_version: str
    selected_candidate_id: str
    selected_weights: FusionWeights
    selected_threshold: float = Field(gt=0.0, lt=1.0)
    false_positive_rate_ceiling: float = Field(ge=0.0, lt=1.0)
    selection_policy_version: str
    candidates: tuple[CandidateEvaluation, ...]
    supervised_baseline: CandidateEvaluation
    anomaly_baseline: CandidateEvaluation
    recommendation_status: RecommendationStatus
    recommendation_rationale: tuple[str, ...]
    validation_groups: tuple[str, ...]
    evaluation_data_accessed: Literal[False]
    held_out_family_accessed: Literal[False]
    protocol_frozen_at: datetime

    @field_validator("protocol_frozen_at")
    @classmethod
    def validate_protocol_frozen_at(cls, value: datetime) -> datetime:
        return require_aware_utc(value)


class ScoreDistributionEvidence(FusionModel):
    sample_class: Literal["benign", "attack"]
    count: int = Field(ge=1)
    minimum: float = Field(ge=0.0, le=1.0)
    maximum: float = Field(ge=0.0, le=1.0)
    mean: float = Field(ge=0.0, le=1.0)
    standard_deviation: float = Field(ge=0.0)
    q25: float = Field(ge=0.0, le=1.0)
    median: float = Field(ge=0.0, le=1.0)
    q75: float = Field(ge=0.0, le=1.0)


class ExperimentIsolationAudit(FusionModel):
    train_rows: int = Field(ge=1)
    validation_rows: int = Field(ge=1)
    evaluation_rows: int = Field(ge=1)
    train_groups: int = Field(ge=1)
    validation_groups: int = Field(ge=1)
    evaluation_groups: int = Field(ge=1)
    group_overlap: tuple[str, ...]
    source_overlap: tuple[str, ...]
    session_overlap: tuple[str, ...]
    scenario_overlap: tuple[str, ...]
    held_out_family_absent_from_train: bool | None = None
    held_out_family_absent_from_validation: bool | None = None
    metadata_and_labels_excluded_from_features: Literal[True]
    future_data_used_for_fit: Literal[False]

    @model_validator(mode="after")
    def validate_isolation(self) -> Self:
        if any(
            (
                self.group_overlap,
                self.source_overlap,
                self.session_overlap,
                self.scenario_overlap,
            )
        ):
            raise ValueError("fusion experiment identities overlap")
        held_out_flags = (
            self.held_out_family_absent_from_train,
            self.held_out_family_absent_from_validation,
        )
        if any(value is False for value in held_out_flags):
            raise ValueError("held-out family entered fit or selection evidence")
        return self


class FeatureRange(FusionModel):
    minimum: float
    maximum: float

    @model_validator(mode="after")
    def validate_order(self) -> Self:
        if self.minimum > self.maximum:
            raise ValueError("feature range is reversed")
        return self


class ParameterShiftAudit(FusionModel):
    shift_id: str
    axis: Literal[
        "flow_duration",
        "packet_rate",
        "packet_size_pattern",
        "connection_frequency",
    ]
    factor: float = Field(gt=1.0, le=2.0)
    relevant_features: tuple[str, ...]
    base_ranges: dict[str, FeatureRange]
    shifted_ranges: dict[str, FeatureRange]
    base_group_count: int = Field(ge=1)
    shifted_group_count: int = Field(ge=1)
    group_overlap: tuple[str, ...]
    result_driven_expansion: Literal[False]
    safe_bounded_simulation: Literal[True]
    network_access: Literal[False]
    external_target: Literal[False]

    @model_validator(mode="after")
    def validate_ranges(self) -> Self:
        expected = set(self.relevant_features)
        if (
            not expected
            or set(self.base_ranges) != expected
            or set(self.shifted_ranges) != expected
            or self.group_overlap
        ):
            raise ValueError("parameter-shift audit evidence is incomplete")
        return self


class ComparisonResult(FusionModel):
    experiment_kind: Literal[
        "known_attack",
        "leave_one_family_out",
        "temporal_holdout",
        "parameter_shift",
    ]
    scenario_id: str
    held_out_family: str | None = None
    shift_axis: str | None = None
    row_count: int = Field(ge=1)
    groups: tuple[str, ...]
    family_distribution: dict[str, int]
    isolation: ExperimentIsolationAudit
    supervised: CandidateEvaluation
    anomaly: CandidateEvaluation
    fusion: CandidateEvaluation
    score_distributions: dict[str, ScoreDistributionEvidence]
    confidence_intervals: dict[str, MetricInterval]
    fusion_minus_supervised: dict[str, float | None]
    fusion_minus_anomaly: dict[str, float | None]
    delta_confidence_intervals: dict[str, MetricInterval]
    fpr_ceiling_satisfied: bool
    recommendation_status: RecommendationStatus
    parameter_shift_audit: ParameterShiftAudit | None = None
    limitations: tuple[str, ...]

    @model_validator(mode="after")
    def validate_experiment_evidence(self) -> Self:
        expected_distributions = {
            f"{mode}.{sample_class}"
            for mode in ("supervised", "anomaly", "fusion")
            for sample_class in ("benign", "attack")
        }
        if set(self.score_distributions) != expected_distributions:
            raise ValueError("comparison score distributions are incomplete")
        if (self.experiment_kind == "parameter_shift") != (self.parameter_shift_audit is not None):
            raise ValueError("parameter-shift audit presence is inconsistent")
        return self


class Phase7DatasetManifest(FusionModel):
    manifest_schema_version: Literal["1.0.0"]
    dataset_id: str
    dataset_version: str
    generator_version: str
    feature_schema_version: str
    row_count: int = Field(ge=1)
    group_count: int = Field(ge=1)
    attack_families: tuple[str, ...]
    family_distribution: dict[str, int]
    dataset_checksum: str
    quality_status: Literal["pass"]
    exact_duplicate_count: int = Field(ge=0)
    feature_duplicate_count: int = Field(ge=0)
    conflicting_label_fingerprint_count: int = Field(ge=0)
    near_duplicate_count: int = Field(ge=0)
    controlled_synthetic_only: Literal[True]
    public_benchmark: Literal[False]
    network_access: Literal[False]
    external_target: Literal[False]
    historical_frozen_test_reused: Literal[False]
    random_seed: int

    @field_validator("dataset_checksum")
    @classmethod
    def validate_dataset_checksum(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("Phase 7 dataset checksum must be SHA-256")
        return normalized


class Phase7SplitManifest(FusionModel):
    manifest_schema_version: Literal["1.0.0"]
    dataset_id: str
    dataset_version: str
    dataset_checksum: str
    time_field: Literal["metadata.observed_at"]
    early_groups: tuple[str, ...]
    middle_groups: tuple[str, ...]
    late_groups: tuple[str, ...]
    row_counts: dict[str, int]
    group_counts: dict[str, int]
    time_ranges: dict[str, tuple[datetime, datetime]]
    group_overlap: tuple[str, ...]
    source_overlap: tuple[str, ...]
    session_overlap: tuple[str, ...]
    scenario_overlap: tuple[str, ...]
    future_data_used_for_fit: Literal[False]
    historical_test_reused: Literal[False]

    @field_validator("dataset_checksum")
    @classmethod
    def validate_split_dataset_checksum(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("Phase 7 split checksum must be SHA-256")
        return normalized

    @field_validator("time_ranges")
    @classmethod
    def validate_time_ranges(
        cls, value: dict[str, tuple[datetime, datetime]]
    ) -> dict[str, tuple[datetime, datetime]]:
        return {
            name: (require_aware_utc(bounds[0]), require_aware_utc(bounds[1]))
            for name, bounds in value.items()
        }

    @model_validator(mode="after")
    def validate_isolation(self) -> Self:
        if any(
            (
                self.group_overlap,
                self.source_overlap,
                self.session_overlap,
                self.scenario_overlap,
            )
        ):
            raise ValueError("Phase 7 split identities overlap")
        required = {"early", "middle", "late"}
        if set(self.row_counts) != required or set(self.group_counts) != required:
            raise ValueError("Phase 7 split counts are incomplete")
        early = self.time_ranges["early"]
        middle = self.time_ranges["middle"]
        late = self.time_ranges["late"]
        if not early[1] < middle[0] or not middle[1] < late[0]:
            raise ValueError("Phase 7 temporal ranges are not strictly ordered")
        return self


class PolicyManifest(FusionModel):
    manifest_schema_version: Literal["1.0.0"]
    policy_id: str
    policy_version: str
    status: Literal["controlled_experiment_evaluated"]
    experiment_id: str
    dataset_id: str
    dataset_version: str
    dataset_manifest_checksum: str
    split_manifest_checksum: str
    experiment_protocol_checksum: str
    feature_schema_version: str
    supervised_model_id: str
    supervised_model_version: str
    supervised_score_semantics: Literal["calibrated supervised probability"]
    anomaly_model_id: str
    anomaly_model_version: str
    anomaly_score_semantics: Literal["bounded normalized anomaly score; not probability"]
    selected_candidate_id: str
    candidate_weights: tuple[FusionWeights, ...]
    selected_weights: FusionWeights
    selected_threshold: float = Field(gt=0.0, lt=1.0)
    selection_policy_version: str
    false_positive_rate_ceiling: float = Field(ge=0.0, lt=1.0)
    recommendation_status: RecommendationStatus
    selection_evidence_checksum: str
    known_evidence_checksum: str
    unseen_evidence_checksum: str
    temporal_evidence_checksum: str
    parameter_shift_evidence_checksum: str
    confidence_interval_checksum: str
    git_commit_sha: str | None
    python_version: str
    dependency_versions: dict[str, str]
    pipeline_verification_only: Literal[True]
    public_benchmark: Literal[False]
    fusion_score_semantics: Literal[
        "experimental suspiciousness score; not probability, risk, severity, or attack confirmation"
    ]
    protocol_frozen_at: datetime
    created_at: datetime

    @field_validator(
        "dataset_manifest_checksum",
        "split_manifest_checksum",
        "experiment_protocol_checksum",
        "selection_evidence_checksum",
        "known_evidence_checksum",
        "unseen_evidence_checksum",
        "temporal_evidence_checksum",
        "parameter_shift_evidence_checksum",
        "confidence_interval_checksum",
    )
    @classmethod
    def validate_checksum(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("fusion evidence checksum must be SHA-256")
        return normalized

    @field_validator("protocol_frozen_at", "created_at")
    @classmethod
    def validate_policy_timestamp(cls, value: datetime) -> datetime:
        return require_aware_utc(value)


class PolicyChecksums(FusionModel):
    checksum_schema_version: Literal["1.0.0"]
    file_inventory: tuple[
        Literal["fusion_policy_manifest.json"],
        Literal["fusion_policy_checksums.json"],
        Literal["fusion_policy_card.md"],
    ]
    manifest_checksum: str
    policy_card_checksum: str

    @field_validator("manifest_checksum", "policy_card_checksum")
    @classmethod
    def validate_file_checksum(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("fusion policy checksum must be SHA-256")
        return normalized
