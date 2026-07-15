"""Threat-hypothesis, investigation-case, and analyst-feedback schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Self
from uuid import UUID, uuid4

from pydantic import Field, field_validator, model_validator

from aegishunt.schemas.base import CoreSchema, Probability, require_aware_utc, utc_now
from aegishunt.schemas.enums import (
    AnalystVerdict,
    CasePriority,
    CaseStatus,
    FeedbackObjectType,
    HypothesisStatus,
    Severity,
)


class ThreatHypothesis(CoreSchema):
    """Structured, explicitly uncertain threat-hunting hypothesis."""

    hypothesis_id: UUID = Field(default_factory=uuid4)
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1)
    confidence: Probability
    severity: Severity
    involved_entities: list[str] = Field(default_factory=list)
    supporting_alert_ids: list[str] = Field(default_factory=list)
    supporting_features: list[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    possible_attack_category: str | None = Field(default=None, max_length=255)
    possible_mitre_mappings: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    alternative_explanations: list[str] = Field(default_factory=list)
    recommended_queries: list[str] = Field(default_factory=list)
    recommended_steps: list[str] = Field(default_factory=list)
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("first_seen", "last_seen", "created_at")
    @classmethod
    def validate_timestamps(cls, value: datetime) -> datetime:
        return require_aware_utc(value)

    @model_validator(mode="after")
    def validate_time_order(self) -> Self:
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must not precede first_seen")
        return self


class InvestigationCase(CoreSchema):
    """Analyst-controlled investigation state and evidence references."""

    case_id: UUID = Field(default_factory=uuid4)
    hypothesis_id: UUID | None = None
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1)
    priority: CasePriority = CasePriority.MEDIUM
    status: CaseStatus = CaseStatus.OPEN
    assigned_to: str | None = Field(default=None, max_length=255)
    evidence_references: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    related_object_ids: list[str] = Field(default_factory=list)
    verdict: AnalystVerdict | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    closed_at: datetime | None = None

    @field_validator("created_at", "updated_at", "closed_at")
    @classmethod
    def validate_timestamps(cls, value: datetime | None) -> datetime | None:
        return None if value is None else require_aware_utc(value)

    @model_validator(mode="after")
    def validate_time_order(self) -> Self:
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at")
        if self.closed_at and self.closed_at < self.created_at:
            raise ValueError("closed_at must not precede created_at")
        return self


class AnalystFeedback(CoreSchema):
    """Explicit analyst verdict attached to a persisted object."""

    feedback_id: UUID = Field(default_factory=uuid4)
    object_type: FeedbackObjectType
    object_id: str = Field(min_length=1, max_length=255)
    verdict: AnalystVerdict
    confidence: Probability
    notes: str = ""
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("created_at")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return require_aware_utc(value)
