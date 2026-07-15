"""Explicit failures for telemetry validation, storage, and job lookup."""

from __future__ import annotations

from uuid import UUID

from aegishunt.errors import AegisHuntError


class IngestionError(AegisHuntError):
    """Base class for expected ingestion failures safe for operators."""

    code = "ingestion_error"


class FilePolicyError(IngestionError):
    """Raised when a filename, media type, or size violates upload policy."""

    code = "file_policy_error"


class TelemetryFormatError(IngestionError):
    """Raised when telemetry content is malformed or unsupported."""

    code = "telemetry_format_error"


class FileStorageError(IngestionError):
    """Raised when controlled staging or atomic storage fails."""

    code = "file_storage_error"


class UnsupportedTelemetryTypeError(IngestionError):
    """Raised when no registered adapter can inspect a telemetry type."""

    code = "unsupported_telemetry_type"


class SampleDataError(IngestionError):
    """Raised when the controlled sample registry or an entry is invalid."""

    code = "sample_data_error"


class IngestionJobNotFoundError(IngestionError):
    """Raised when an ingestion job identifier is unknown."""

    code = "ingestion_job_not_found"


class IngestionJobFailedError(IngestionError):
    """Expose a persisted failed job together with its safe root cause."""

    code = "ingestion_job_failed"

    def __init__(self, job_id: UUID, cause: IngestionError) -> None:
        self.job_id = job_id
        self.cause = cause
        super().__init__(str(cause))
