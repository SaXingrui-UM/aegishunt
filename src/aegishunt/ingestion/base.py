"""Common telemetry adapter interface and explicit registry."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from aegishunt.ingestion.errors import UnsupportedTelemetryTypeError
from aegishunt.ingestion.schemas import IngestionInspection
from aegishunt.schemas.enums import SourceType


@dataclass(frozen=True, slots=True)
class FilePolicy:
    """Allowed suffix and declared media-type policy for one adapter."""

    extensions: frozenset[str]
    content_types: frozenset[str]


class TelemetryIngestor(ABC):
    """Inspect one safely staged file without producing later-phase records."""

    source_type: SourceType
    policy: FilePolicy

    @abstractmethod
    def inspect(self, path: Path, *, max_records: int) -> IngestionInspection:
        """Validate content and return a bounded record count plus safe metadata."""


class IngestorRegistry:
    """Resolve adapters by explicit source type without dynamic imports."""

    def __init__(self, ingestors: tuple[TelemetryIngestor, ...]) -> None:
        self._ingestors = {ingestor.source_type: ingestor for ingestor in ingestors}
        if len(self._ingestors) != len(ingestors):
            raise ValueError("telemetry ingestor source types must be unique")

    def get(self, source_type: SourceType) -> TelemetryIngestor:
        """Return a registered adapter or fail with a safe explicit error."""

        try:
            return self._ingestors[source_type]
        except KeyError as exc:
            raise UnsupportedTelemetryTypeError(
                f"no telemetry ingestor is registered for {source_type.value}"
            ) from exc
