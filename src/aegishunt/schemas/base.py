"""Common schema types and validation helpers."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, JsonValue

Probability = Annotated[float, Field(ge=0.0, le=1.0)]
NonNegativeFloat = Annotated[float, Field(ge=0.0)]
NonNegativeInt = Annotated[int, Field(ge=0)]
Port = Annotated[int, Field(ge=0, le=65_535)]
JsonObject = dict[str, JsonValue]


class CoreSchema(BaseModel):
    """Strict immutable base for persisted domain records."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        from_attributes=True,
        populate_by_name=True,
    )


def utc_now() -> datetime:
    """Return an aware UTC timestamp for deterministic persistence semantics."""

    return datetime.now(UTC)


def require_aware_utc(value: datetime) -> datetime:
    """Reject naive timestamps and normalize aware values to UTC."""

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include timezone information")
    return value.astimezone(UTC)
