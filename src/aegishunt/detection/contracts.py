"""Strict score, risk-policy, and decision contracts for Phase 8."""

from __future__ import annotations

import math
from datetime import datetime
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegishunt.datasets.schemas import SHA256_PATTERN
from aegishunt.schemas.base import require_aware_utc
from aegishunt.schemas.enums import Severity

RiskScoreSource = Literal[
    "fusion_score",
    "supervised_probability",
    "normalized_anomaly_score",
]
FusionRecommendation = Literal["inconclusive"]


class DetectionModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class SeverityBand(DetectionModel):
    severity: Severity
    minimum_score: float = Field(ge=0.0, le=1.0)


class RiskPolicy(DetectionModel):
    """Configuration-controlled identity mapping from one declared score to risk."""

    policy_schema_version: Literal["1.0.0"]
    policy_id: str = Field(min_length=1, max_length=255)
    policy_version: str = Field(min_length=1, max_length=64)
    score_source: RiskScoreSource
    required_supervised_model_id: str
    required_supervised_model_version: str
    required_anomaly_model_id: str
    required_anomaly_model_version: str
    required_fusion_policy_id: str
    required_fusion_policy_version: str
    required_fusion_policy_checksum: str
    required_feature_schema_version: str
    required_fusion_recommendation: FusionRecommendation
    alert_threshold: float = Field(ge=0.0, le=1.0)
    severity_bands: tuple[SeverityBand, ...]
    created_at: datetime
    score_semantics: Literal[
        "operational suspiciousness for analyst triage; not attack probability"
    ]
    controlled_pipeline_only: Literal[True]

    @field_validator("required_fusion_policy_checksum")
    @classmethod
    def validate_checksum(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("fusion policy checksum must be SHA-256")
        return normalized

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return require_aware_utc(value)

    @model_validator(mode="after")
    def validate_bands(self) -> Self:
        if not self.severity_bands:
            raise ValueError("severity bands cannot be empty")
        minimums = tuple(item.minimum_score for item in self.severity_bands)
        if minimums[0] != 0.0 or any(
            left >= right for left, right in zip(minimums, minimums[1:], strict=False)
        ):
            raise ValueError("severity bands must start at zero and increase without overlap")
        severities = tuple(item.severity for item in self.severity_bands)
        expected = tuple(Severity)
        if severities != expected:
            raise ValueError("severity bands must declare every severity in stable order")
        return self


class LoadedRiskPolicy(DetectionModel):
    policy: RiskPolicy
    configuration_checksum: str

    @field_validator("configuration_checksum")
    @classmethod
    def validate_configuration_checksum(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("risk policy configuration checksum must be SHA-256")
        return normalized


class VerifiedScores(DetectionModel):
    """Aligned outputs from verified Phase 5, 6, and 7 contracts."""

    supervised_label: Literal[0, 1]
    supervised_probability: float = Field(ge=0.0, le=1.0)
    supervised_threshold: float = Field(gt=0.0, lt=1.0)
    anomaly_raw_score: float
    normalized_anomaly_score: float = Field(ge=0.0, le=1.0)
    anomaly_threshold: float = Field(ge=0.0, le=1.0)
    fusion_score: float = Field(ge=0.0, le=1.0)
    fusion_threshold: float = Field(gt=0.0, lt=1.0)
    supervised_model_id: str
    supervised_model_version: str
    anomaly_model_id: str
    anomaly_model_version: str
    fusion_policy_id: str
    fusion_policy_version: str
    fusion_policy_checksum: str
    fusion_recommendation: FusionRecommendation
    feature_schema_version: str
    scored_at: datetime

    @field_validator("anomaly_raw_score")
    @classmethod
    def validate_raw_score(cls, value: float) -> float:
        if isinstance(value, bool) or not math.isfinite(value):
            raise ValueError("raw anomaly score must be finite")
        return value

    @field_validator("fusion_policy_checksum")
    @classmethod
    def validate_policy_checksum(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("verified fusion policy checksum must be SHA-256")
        return normalized

    @field_validator("scored_at")
    @classmethod
    def validate_scored_at(cls, value: datetime) -> datetime:
        return require_aware_utc(value)


class RiskDecision(DetectionModel):
    risk_score: float = Field(ge=0.0, le=1.0)
    score_source: RiskScoreSource
    severity: Severity
    alert_threshold: float = Field(ge=0.0, le=1.0)
    alert_required: bool
    risk_policy_id: str
    risk_policy_version: str
    risk_policy_checksum: str
    semantics: Literal[
        "operational suspiciousness for analyst triage; not attack probability"
    ]

    @field_validator("risk_policy_checksum")
    @classmethod
    def validate_risk_checksum(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("risk decision policy checksum must be SHA-256")
        return normalized
