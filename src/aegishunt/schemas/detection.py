"""Detection, alert, and correlation-group schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Self
from uuid import UUID, uuid4

from pydantic import Field, field_validator, model_validator

from aegishunt.schemas.base import CoreSchema, JsonObject, Probability, require_aware_utc, utc_now
from aegishunt.schemas.enums import AlertStatus, Severity


class DetectionResult(CoreSchema):
    """Versioned detection scores for one network flow."""

    detection_id: UUID = Field(default_factory=uuid4)
    flow_id: UUID
    supervised_label: str | None = Field(default=None, max_length=255)
    supervised_probability: Probability | None = None
    anomaly_score: float | None = None
    normalized_anomaly_score: Probability | None = None
    behavioral_rule_score: Probability | None = None
    combined_risk_score: Probability
    severity: Severity
    model_versions: dict[str, str] = Field(default_factory=dict)
    explanation: JsonObject = Field(default_factory=dict)
    detected_at: datetime = Field(default_factory=utc_now)

    @field_validator("detected_at")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return require_aware_utc(value)


class SecurityAlert(CoreSchema):
    """Human-reviewable alert derived from a detection record."""

    alert_id: UUID = Field(default_factory=uuid4)
    detection_id: UUID
    alert_type: str = Field(min_length=1, max_length=255)
    severity: Severity
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1)
    involved_entities: list[str] = Field(default_factory=list)
    evidence: JsonObject = Field(default_factory=dict)
    reason_codes: list[str] = Field(default_factory=list)
    status: AlertStatus = AlertStatus.OPEN
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("created_at")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return require_aware_utc(value)


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
