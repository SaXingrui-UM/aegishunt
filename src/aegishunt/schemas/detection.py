"""Detection, alert, and correlation-group schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Self
from uuid import UUID, uuid4

from pydantic import AliasChoices, Field, field_validator, model_validator

from aegishunt.schemas.base import CoreSchema, JsonObject, Probability, require_aware_utc, utc_now
from aegishunt.schemas.enums import AlertStatus, AnalystVerdict, Severity


class DetectionResult(CoreSchema):
    """Versioned detection scores for one network flow."""

    detection_id: UUID = Field(default_factory=uuid4)
    flow_id: UUID
    supervised_label: str = Field(max_length=255)
    supervised_probability: Probability
    supervised_threshold: float = Field(gt=0.0, lt=1.0, allow_inf_nan=False)
    anomaly_raw_score: float = Field(
        validation_alias=AliasChoices("anomaly_raw_score", "anomaly_score"),
        allow_inf_nan=False,
    )
    normalized_anomaly_score: Probability
    anomaly_threshold: Probability
    fusion_score: Probability
    fusion_threshold: float = Field(gt=0.0, lt=1.0, allow_inf_nan=False)
    behavioral_rule_score: Probability | None = None
    risk_score: Probability = Field(
        validation_alias=AliasChoices("risk_score", "combined_risk_score")
    )
    risk_source: Literal[
        "fusion_score",
        "supervised_probability",
        "normalized_anomaly_score",
    ]
    severity: Severity
    alert_threshold: Probability
    model_versions: dict[str, str] = Field(min_length=2)
    policy_versions: dict[str, str] = Field(min_length=2)
    policy_checksums: dict[str, str] = Field(min_length=2)
    feature_schema_version: str = Field(min_length=1, max_length=64)
    reason_codes: list[str] = Field(default_factory=list)
    explanation: JsonObject = Field(min_length=1)
    detected_at: datetime = Field(default_factory=utc_now)

    @field_validator("detected_at")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return require_aware_utc(value)

    @field_validator("model_versions", "policy_versions")
    @classmethod
    def validate_identity_maps(cls, values: dict[str, str]) -> dict[str, str]:
        if any(not key.strip() or not value.strip() for key, value in values.items()):
            raise ValueError("model and policy identities cannot be blank")
        return values

    @field_validator("policy_checksums")
    @classmethod
    def validate_policy_checksums(cls, values: dict[str, str]) -> dict[str, str]:
        normalized = {key: value.strip().lower() for key, value in values.items()}
        if any(
            not key.strip()
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
            for key, value in normalized.items()
        ):
            raise ValueError("policy identity checksums must be SHA-256")
        return normalized


class SecurityAlert(CoreSchema):
    """Human-reviewable alert derived from a detection record."""

    alert_id: UUID = Field(default_factory=uuid4)
    detection_id: UUID
    alert_type: str = Field(min_length=1, max_length=255)
    severity: Severity
    risk_score: Probability
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1)
    involved_entities: list[str] = Field(min_length=1)
    evidence: JsonObject = Field(min_length=1)
    reason_codes: list[str] = Field(min_length=1)
    explanation: JsonObject = Field(min_length=1)
    model_versions: dict[str, str] = Field(min_length=1)
    policy_versions: dict[str, str] = Field(min_length=1)
    status: AlertStatus = AlertStatus.OPEN
    analyst_verdict: AnalystVerdict | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @field_validator("created_at", "updated_at")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return require_aware_utc(value)

    @model_validator(mode="after")
    def validate_time_order(self) -> Self:
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at")
        return self


class AlertGroup(CoreSchema):
    """Deterministic correlation group referencing source alerts."""

    group_id: UUID = Field(default_factory=uuid4)
    alert_ids: list[str] = Field(min_length=1)
    entity_keys: list[str] = Field(default_factory=list)
    correlation_score: Probability
    first_seen: datetime
    last_seen: datetime
    summary: str = Field(min_length=1)

    @field_validator("first_seen", "last_seen")
    @classmethod
    def validate_timestamps(cls, value: datetime) -> datetime:
        return require_aware_utc(value)

    @model_validator(mode="after")
    def validate_time_order(self) -> Self:
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must not precede first_seen")
        return self
