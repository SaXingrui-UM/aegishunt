"""Strict data-only contracts for feedback exports and retraining candidates."""

from __future__ import annotations

import math
from datetime import datetime
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegishunt.flows.registry import FEATURE_SCHEMA_VERSION, feature_names
from aegishunt.schemas.base import JsonObject, require_aware_utc


class ArtifactContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class FeedbackExportManifest(ArtifactContract):
    export_id: str
    export_version: str
    export_schema_version: Literal["1.0.0"]
    feedback_schema_version: Literal["1.0.0"]
    filters: JsonObject
    record_count: int = Field(ge=0)
    object_type_counts: dict[str, int]
    verdict_counts: dict[str, int]
    source_feedback_ids: tuple[str, ...]
    generated_at: datetime
    generated_by: str
    git_commit: str | None
    database_schema_version: int
    file_inventory: tuple[str, ...]
    limitations: tuple[str, ...]

    @field_validator("generated_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return require_aware_utc(value)


class CandidateRow(ArtifactContract):
    candidate_id: str
    feature_schema_version: str
    feature_names: tuple[str, ...]
    feature_values: tuple[float, ...]
    candidate_label: Literal["malicious", "benign"]
    label_mapping_version: Literal["1.0.0"]
    source_flow_id: str
    source_detection_id: str
    source_alert_id: str
    supporting_feedback_ids: tuple[str, ...]
    confidence: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    provenance: JsonObject
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return require_aware_utc(value)

    @model_validator(mode="after")
    def validate_features(self) -> Self:
        if self.feature_schema_version != FEATURE_SCHEMA_VERSION:
            raise ValueError("candidate feature schema does not match Phase 3")
        if self.feature_names != feature_names() or len(self.feature_values) != len(
            self.feature_names
        ):
            raise ValueError("candidate feature order does not match Phase 3")
        if any(not math.isfinite(value) for value in self.feature_values):
            raise ValueError("candidate feature values must be finite")
        return self


class CandidateExclusion(ArtifactContract):
    feedback_id: str
    object_id: str
    reason: str


class CandidateConflict(ArtifactContract):
    flow_id: str
    feedback_ids: tuple[str, ...]
    labels: tuple[str, ...]
    reason: Literal["conflicting analyst feedback"] = "conflicting analyst feedback"


class CandidateManifest(ArtifactContract):
    dataset_id: str
    dataset_version: str
    candidate_dataset_schema_version: Literal["1.0.0"]
    status: Literal["retraining_candidate"] = "retraining_candidate"
    eligibility_status: Literal[
        "requires_manual_review", "insufficient_records", "empty"
    ]
    candidate_count: int = Field(ge=0)
    exclusion_count: int = Field(ge=0)
    conflict_count: int = Field(ge=0)
    feature_schema_version: str
    feature_names: tuple[str, ...]
    label_mapping_version: Literal["1.0.0"]
    source_feedback_ids: tuple[str, ...]
    generated_at: datetime
    git_commit: str | None
    database_schema_version: int
    file_inventory: tuple[str, ...]
    requirements: tuple[str, ...]

    @field_validator("generated_at")
    @classmethod
    def validate_generated_at(cls, value: datetime) -> datetime:
        return require_aware_utc(value)
