"""Model-version metadata schema without model loading behavior."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from pydantic import Field, field_validator

from aegishunt.schemas.base import CoreSchema, JsonObject, require_aware_utc, utc_now
from aegishunt.schemas.enums import ModelStatus, ModelType


class ModelVersion(CoreSchema):
    """Immutable provenance metadata for a controlled future model artifact."""

    model_id: UUID = Field(default_factory=uuid4)
    model_type: ModelType
    version: str = Field(min_length=1, max_length=128)
    algorithm: str = Field(min_length=1, max_length=255)
    feature_schema: JsonObject = Field(default_factory=dict)
    training_dataset: str = Field(min_length=1, max_length=512)
    training_config: JsonObject = Field(default_factory=dict)
    metrics: JsonObject = Field(default_factory=dict)
    artifact_path: str = Field(min_length=1, max_length=1024)
    created_at: datetime = Field(default_factory=utc_now)
    status: ModelStatus = ModelStatus.CANDIDATE

    @field_validator("created_at")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return require_aware_utc(value)
