"""Structured JSON and JSON Lines event validation."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import JsonValue, TypeAdapter, ValidationError

from aegishunt.ingestion.base import FilePolicy, TelemetryIngestor
from aegishunt.ingestion.errors import TelemetryFormatError
from aegishunt.ingestion.schemas import IngestionInspection
from aegishunt.schemas.enums import SourceType

_JSON_OBJECT = TypeAdapter(dict[str, JsonValue])


def _reject_non_finite(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def _validate_event(value: object, *, position: str) -> None:
    try:
        _JSON_OBJECT.validate_python(value)
    except ValidationError as exc:
        raise TelemetryFormatError(f"JSON event at {position} must be an object") from exc


class JsonEventIngestor(TelemetryIngestor):
    """Validate structured event objects without interpreting their semantics."""

    source_type = SourceType.JSON_EVENT
    policy = FilePolicy(
        extensions=frozenset({".json", ".jsonl", ".ndjson"}),
        content_types=frozenset(
            {
                "application/json",
                "application/jsonl",
                "application/x-ndjson",
                "text/plain",
            }
        ),
    )

    def inspect(self, path: Path, *, max_records: int) -> IngestionInspection:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise TelemetryFormatError("JSON telemetry must use UTF-8 text encoding") from exc
        except OSError as exc:
            raise TelemetryFormatError("unable to read staged JSON telemetry") from exc
        if not text.strip():
            raise TelemetryFormatError("JSON telemetry is empty")

        try:
            if path.suffix.lower() in {".jsonl", ".ndjson"}:
                count = 0
                for line_number, line in enumerate(text.splitlines(), start=1):
                    if not line.strip():
                        raise TelemetryFormatError(
                            f"JSON Lines entry {line_number} is blank"
                        )
                    value = json.loads(line, parse_constant=_reject_non_finite)
                    _validate_event(value, position=f"line {line_number}")
                    count = line_number
                    if count > max_records:
                        raise TelemetryFormatError(
                            "JSON telemetry contains more than the configured "
                            f"{max_records} record limit"
                        )
                container = "json_lines"
            else:
                value = json.loads(text, parse_constant=_reject_non_finite)
                events = value if isinstance(value, list) else [value]
                if len(events) > max_records:
                    raise TelemetryFormatError(
                        "JSON telemetry contains more than the configured "
                        f"{max_records} record limit"
                    )
                for index, event in enumerate(events):
                    _validate_event(event, position=f"index {index}")
                count = len(events)
                container = "json_array" if isinstance(value, list) else "json_object"
        except json.JSONDecodeError as exc:
            raise TelemetryFormatError(
                f"JSON telemetry is malformed near line {exc.lineno}, column {exc.colno}"
            ) from exc
        except ValueError as exc:
            raise TelemetryFormatError("JSON telemetry contains a non-finite number") from exc

        return IngestionInspection(
            records_processed=count,
            metadata={"container": container},
        )
