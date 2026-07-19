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
    threshold: float = Field(gt=0.0, lt=1.0)
    metrics: AnomalyMetrics
    satisfies_fpr_ceiling: bool
    validation_only: Literal[True]

    @model_validator(mode="after")
    def validate_mode(self) -> Self:
        if self.mode == "dual_engine_fusion":
            if self.weights is None or not self.weights.is_dual_engine:
                raise ValueError("dual-engine evidence requires two positive weights")
        elif self.weights is not None:
            raise ValueError("baseline evidence cannot masquerade as weighted fusion")
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
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return require_aware_utc(value)


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
    supervised: CandidateEvaluation
    anomaly: CandidateEvaluation
    fusion: CandidateEvaluation
    confidence_intervals: dict[str, MetricInterval]
    fusion_minus_supervised: dict[str, float | None]
    fusion_minus_anomaly: dict[str, float | None]
    delta_confidence_intervals: dict[str, MetricInterval]
    fpr_ceiling_satisfied: bool
    recommendation_status: RecommendationStatus
    limitations: tuple[str, ...]


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
    anomaly_score_semantics: Literal[
        "bounded normalized anomaly score; not probability"
    ]
    selected_candidate_id: str
    selected_weights: FusionWeights
    selected_threshold: float = Field(gt=0.0, lt=1.0)
    selection_policy_version: str
    false_positive_rate_ceiling: float = Field(ge=0.0, lt=1.0)
    recommendation_status: RecommendationStatus
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
    created_at: datetime

    @field_validator(
        "dataset_manifest_checksum",
        "split_manifest_checksum",
        "experiment_protocol_checksum",
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

    @field_validator("created_at")
    @classmethod
    def validate_policy_timestamp(cls, value: datetime) -> datetime:
        return require_aware_utc(value)


class PolicyChecksums(FusionModel):
    checksum_schema_version: Literal["1.0.0"]
    manifest_checksum: str
    policy_card_checksum: str

    @field_validator("manifest_checksum", "policy_card_checksum")
    @classmethod
    def validate_file_checksum(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("fusion policy checksum must be SHA-256")
        return normalized
