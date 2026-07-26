"""Validated ingestion job, inspection, stored-file, and sample contracts."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import Field

from aegishunt.schemas.base import CoreSchema, JsonObject, NonNegativeInt, Probability
from aegishunt.schemas.enums import IngestionMode, LifecycleStatus, SourceType
from aegishunt.schemas.telemetry import TelemetrySource


class IngestionInspection(CoreSchema):
    """Bounded adapter result without derived flows or features."""

    records_processed: NonNegativeInt
    metadata: JsonObject = Field(default_factory=dict)


class StagedFile(CoreSchema):
    """Internal metadata for an untrusted file staged under a controlled root."""

    path: str
    original_filename: str
    safe_extension: str
    checksum: str
    byte_size: NonNegativeInt
    content_type: str | None = None


class StoredFile(CoreSchema):
    """Safe relative storage reference returned after atomic commit."""

    stored_filename: str
    checksum: str
    byte_size: NonNegativeInt


class IngestionJobError(CoreSchema):
    """Safe error details persisted for analyst inspection."""

    code: str = Field(min_length=1, max_length=128)
    message: str = Field(min_length=1, max_length=1_024)


class IngestionJob(CoreSchema):
    """Operator-facing projection of a durable TelemetrySource job."""

    job_id: UUID
    source_type: SourceType
    ingestion_mode: IngestionMode
    status: LifecycleStatus
    progress: Probability
    original_filename: str
    records_processed: NonNegativeInt
    checksum: str | None = None
    stored_filename: str | None = None
    byte_size: NonNegativeInt | None = None
    content_type: str | None = None
    format_metadata: JsonObject = Field(default_factory=dict)
    error: IngestionJobError | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None

    @classmethod
    def from_source(cls, source: TelemetrySource) -> IngestionJob:
        """Build a validated public job view from safe source metadata."""

        metadata = source.source_metadata
        error_code = metadata.get("error_code")
        error_message = metadata.get("error_message")
        error = None
        if isinstance(error_code, str) and isinstance(error_message, str):
            error = IngestionJobError(code=error_code, message=error_message)
        format_metadata = metadata.get("format_metadata", {})
        raw_progress = metadata.get("progress", 0.0)
        progress = (
            float(raw_progress)
            if isinstance(raw_progress, (int, float)) and not isinstance(raw_progress, bool)
            else 0.0
        )
        raw_stored_filename = metadata.get("stored_filename")
        stored_filename = raw_stored_filename if isinstance(raw_stored_filename, str) else None
        raw_byte_size = metadata.get("byte_size")
        byte_size = (
            raw_byte_size
            if isinstance(raw_byte_size, int) and not isinstance(raw_byte_size, bool)
            else None
        )
        raw_content_type = metadata.get("content_type")
        content_type = raw_content_type if isinstance(raw_content_type, str) else None
        return cls(
            job_id=source.source_id,
            source_type=source.source_type,
            ingestion_mode=source.ingestion_mode,
            status=source.status,
            progress=progress,
            original_filename=source.filename_or_interface,
            records_processed=source.records_processed,
            checksum=source.checksum,
            stored_filename=stored_filename,
            byte_size=byte_size,
            content_type=content_type,
            format_metadata=format_metadata if isinstance(format_metadata, dict) else {},
            error=error,
            started_at=source.started_at,
            completed_at=source.completed_at,
        )


class IngestionJobPage(CoreSchema):
    """Paginated ingestion job response."""

    items: list[IngestionJob]
    total: NonNegativeInt
    limit: int = Field(ge=1, le=100)
    offset: NonNegativeInt
    next_offset: NonNegativeInt | None
    has_more: bool


class SampleDescriptor(CoreSchema):
    """Public metadata for one checksum-verified controlled sample."""

    sample_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    filename: str = Field(min_length=1, max_length=255)
    source_type: SourceType
    content_type: str = Field(min_length=1, max_length=255)
    checksum: str = Field(pattern=r"^[0-9a-f]{64}$")
    description: str = Field(min_length=1, max_length=512)
    synthetic: bool
