"""Typed immutable contracts for Phase 9 correlation."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aegishunt.schemas.base import JsonObject, require_aware_utc

EntityType = Literal[
    "source_ip",
    "destination_ip",
    "source_host",
    "destination_host",
    "user",
    "protocol",
    "service",
    "flow_id",
    "capture_session_id",
    "source_destination_pair",
]


class CorrelationModel(BaseModel):
    """Strict immutable correlation model."""

    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class EntityKey(CorrelationModel):
    """Typed normalized entity identity used only for correlation."""

    entity_type: EntityType
    value: str = Field(min_length=1, max_length=512)

    @property
    def serialized(self) -> str:
        return f"{self.entity_type}:{self.value}"


class IndexedAlert(CorrelationModel):
    """One immutable alert with canonical event time and entity evidence."""

    alert_id: str
    event_start: datetime
    event_end: datetime
    entity_keys: tuple[EntityKey, ...] = Field(min_length=1)
    risk_score: float = Field(ge=0.0, le=1.0)
    severity: str
    alert_type: str
    reason_codes: tuple[str, ...]
    analyst_verdict: str | None
    model_versions: dict[str, str]
    policy_versions: dict[str, str]
    observed_facts: JsonObject
    evidence_snapshot: JsonObject

    @field_validator("event_start", "event_end")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        return require_aware_utc(value)


class RuleMatch(CorrelationModel):
    """Versioned, explainable result of one correlation rule."""

    rule_id: str
    version: str
    matched_alert_ids: tuple[str, ...] = Field(min_length=2)
    required_entity_keys: tuple[str, ...] = Field(min_length=1)
    evidence: JsonObject = Field(min_length=1)
    limitations: tuple[str, ...] = Field(min_length=1)


class CorrelationScoreComponents(CorrelationModel):
    """Bounded components retained with every group score."""

    risk: float = Field(ge=0.0, le=1.0)
    alert_count: float = Field(ge=0.0, le=1.0)
    evidence_diversity: float = Field(ge=0.0, le=1.0)
    temporal_density: float = Field(ge=0.0, le=1.0)


class ScoredCorrelation(CorrelationModel):
    """One bounded non-probabilistic correlation score."""

    score: float = Field(ge=0.0, le=1.0)
    components: CorrelationScoreComponents
    semantics: Literal[
        "correlation evidence strength for analyst triage; not attack probability"
    ] = "correlation evidence strength for analyst triage; not attack probability"
