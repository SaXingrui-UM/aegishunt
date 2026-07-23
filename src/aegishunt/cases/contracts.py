"""Data-only contracts for deterministic investigation-case reports."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aegishunt.schemas.base import require_aware_utc


class CaseReportManifest(BaseModel):
    """Identity and integrity metadata for one non-overwriting case report."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    report_id: str = Field(min_length=1, max_length=255)
    report_version: str = Field(min_length=1, max_length=128)
    report_schema_version: Literal["1.0.0"]
    case_schema_version: Literal["1.0.0"]
    case_id: str
    generated_at: datetime
    generated_by: str
    git_commit: str | None
    database_schema_version: int
    file_inventory: tuple[str, ...]
    evidence_reference_count: int = Field(ge=1)
    note_count: int = Field(ge=0)
    feedback_count: int = Field(ge=0)
    limitations: tuple[str, ...]

    @field_validator("generated_at")
    @classmethod
    def validate_generated_at(cls, value: datetime) -> datetime:
        return require_aware_utc(value)
