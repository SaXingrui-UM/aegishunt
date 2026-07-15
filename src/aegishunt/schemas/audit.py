"""Append-only audit-event schema."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from pydantic import Field, field_validator

from aegishunt.schemas.base import CoreSchema, JsonObject, require_aware_utc, utc_now


class AuditEvent(CoreSchema):
    """One immutable operator or system action recorded with context."""

    audit_id: UUID = Field(default_factory=uuid4)
    actor: str = Field(min_length=1, max_length=255)
    action: str = Field(min_length=1, max_length=255)
    object_type: str = Field(min_length=1, max_length=255)
    object_id: str | None = Field(default=None, max_length=255)
    details: JsonObject = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("created_at")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return require_aware_utc(value)
