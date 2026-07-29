"""Streaming structured JSON and JSON Lines event validation."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO, TextIO

from pydantic import JsonValue, TypeAdapter, ValidationError

from aegishunt.ingestion.base import FilePolicy, TelemetryIngestor
from aegishunt.ingestion.errors import TelemetryFormatError
from aegishunt.ingestion.schemas import IngestionInspection
from aegishunt.schemas.enums import SourceType

_JSON_OBJECT = TypeAdapter(dict[str, JsonValue])
_STREAM_CHUNK_CHARACTERS = 65_536


def _reject_non_finite(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def _validate_depth(value: object, *, maximum_depth: int, position: str) -> None:
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > maximum_depth:
            raise TelemetryFormatError(
                f"JSON event at {position} exceeds the configured nesting depth"
            )
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)


def _validate_structural_depth(
    text: str,
    *,
    maximum_depth: int,
    position: str,
) -> None:
    """Reject excessive structure before recursive decoder materialization."""

    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > maximum_depth:
                raise TelemetryFormatError(
                    f"JSON event at {position} exceeds the configured nesting depth"
                )
        elif character in "]}":
            depth = max(0, depth - 1)


def _validate_event(
    value: object,
    *,
    position: str,
    maximum_depth: int,
) -> None:
    try:
        event = _JSON_OBJECT.validate_python(value)
    except ValidationError as exc:
        raise TelemetryFormatError(f"JSON event at {position} must be an object") from exc
    _validate_depth(event, maximum_depth=maximum_depth, position=position)


def _read_more(stream: TextIO, buffer: str) -> tuple[str, bool]:
    chunk = stream.read(_STREAM_CHUNK_CHARACTERS)
    return buffer + chunk, not chunk


def _strip_leading_whitespace(stream: TextIO, buffer: str) -> tuple[str, bool]:
    eof = False
    while True:
        buffer = buffer.lstrip()
        if buffer or eof:
            return buffer, eof
        buffer, eof = _read_more(stream, buffer)


def _decode_value(
    stream: TextIO,
    buffer: str,
    *,
    maximum_record_bytes: int,
    maximum_depth: int,
    position: str,
) -> tuple[object, str]:
    decoder = json.JSONDecoder(parse_constant=_reject_non_finite)
    eof = False
    buffer, eof = _strip_leading_whitespace(stream, buffer)
    while True:
        _validate_structural_depth(
            buffer,
            maximum_depth=maximum_depth,
            position=position,
        )
        try:
            value, end = decoder.raw_decode(buffer)
        except json.JSONDecodeError as exc:
            if eof:
                raise
            if len(buffer.encode("utf-8")) > maximum_record_bytes:
                raise TelemetryFormatError(
                    "JSON event exceeds the configured per-record byte limit"
                ) from exc
            buffer, eof = _read_more(stream, buffer)
            continue
        if len(buffer[:end].encode("utf-8")) > maximum_record_bytes:
            raise TelemetryFormatError(
                "JSON event exceeds the configured per-record byte limit"
            )
        return value, buffer[end:]


def _require_only_whitespace(stream: TextIO, buffer: str) -> None:
    if buffer.strip():
        raise TelemetryFormatError("JSON telemetry has trailing non-whitespace content")
    for chunk in iter(lambda: stream.read(_STREAM_CHUNK_CHARACTERS), ""):
        if chunk.strip():
            raise TelemetryFormatError("JSON telemetry has trailing non-whitespace content")


def _iter_json_array(
    stream: TextIO,
    buffer: str,
    *,
    maximum_record_bytes: int,
    maximum_depth: int,
) -> Iterator[tuple[int, object]]:
    index = 0
    expect_value = True
    while True:
        buffer, eof = _strip_leading_whitespace(stream, buffer)
        if not buffer:
            raise TelemetryFormatError("JSON array is not terminated")
        if expect_value and buffer[0] == "]":
            if index:
                raise TelemetryFormatError("JSON array has a trailing comma")
            _require_only_whitespace(stream, buffer[1:])
            return
        if not expect_value:
            separator = buffer[0]
            buffer = buffer[1:]
            if separator == "]":
                _require_only_whitespace(stream, buffer)
                return
            if separator != ",":
                raise TelemetryFormatError("JSON array entries must be comma-separated")
            expect_value = True
            continue
        if eof:
            raise TelemetryFormatError("JSON array is not terminated")
        value, buffer = _decode_value(
            stream,
            buffer,
            maximum_record_bytes=maximum_record_bytes,
            maximum_depth=maximum_depth,
            position=f"index {index}",
        )
        yield index, value
        index += 1
        expect_value = False


def _json_lines(
    stream: BinaryIO,
    *,
    max_records: int,
    maximum_record_bytes: int,
    maximum_depth: int,
) -> int:
    count = 0
    line_number = 0
    while raw_line := stream.readline(maximum_record_bytes + 1):
        line_number += 1
        if len(raw_line) > maximum_record_bytes:
            raise TelemetryFormatError(
                f"JSON Lines entry {line_number} exceeds the configured per-record byte limit"
            )
        try:
            line = raw_line.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise TelemetryFormatError("JSON telemetry must use UTF-8 text encoding") from exc
        if not line.strip():
            raise TelemetryFormatError(f"JSON Lines entry {line_number} is blank")
        _validate_structural_depth(
            line,
            maximum_depth=maximum_depth,
            position=f"line {line_number}",
        )
        value = json.loads(line, parse_constant=_reject_non_finite)
        _validate_event(
            value,
            position=f"line {line_number}",
            maximum_depth=maximum_depth,
        )
        count += 1
        if count > max_records:
            raise TelemetryFormatError(
                "JSON telemetry contains more than the configured "
                f"{max_records} record limit"
            )
    if not count:
        raise TelemetryFormatError("JSON telemetry is empty")
    return count


class JsonEventIngestor(TelemetryIngestor):
    """Validate structured event objects with bounded incremental parsing."""

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

    def __init__(
        self,
        *,
        maximum_record_bytes: int = 1_048_576,
        maximum_depth: int = 64,
    ) -> None:
        if maximum_record_bytes < 1 or maximum_depth < 1:
            raise ValueError("JSON safety limits must be positive")
        self._maximum_record_bytes = maximum_record_bytes
        self._maximum_depth = maximum_depth

    def inspect(self, path: Path, *, max_records: int) -> IngestionInspection:
        try:
            if path.suffix.lower() in {".jsonl", ".ndjson"}:
                with path.open("rb") as binary_stream:
                    count = _json_lines(
                        binary_stream,
                        max_records=max_records,
                        maximum_record_bytes=self._maximum_record_bytes,
                        maximum_depth=self._maximum_depth,
                    )
                return IngestionInspection(
                    records_processed=count,
                    metadata={"container": "json_lines"},
                )

            with path.open("r", encoding="utf-8") as text_stream:
                prefix, eof = _strip_leading_whitespace(text_stream, "")
                if not prefix:
                    raise TelemetryFormatError("JSON telemetry is empty")
                if prefix[0] == "[":
                    count = 0
                    for index, event in _iter_json_array(
                        text_stream,
                        prefix[1:],
                        maximum_record_bytes=self._maximum_record_bytes,
                        maximum_depth=self._maximum_depth,
                    ):
                        _validate_event(
                            event,
                            position=f"index {index}",
                            maximum_depth=self._maximum_depth,
                        )
                        count = index + 1
                        if count > max_records:
                            raise TelemetryFormatError(
                                "JSON telemetry contains more than the configured "
                                f"{max_records} record limit"
                            )
                    container = "json_array"
                else:
                    if eof and len(prefix.encode("utf-8")) > self._maximum_record_bytes:
                        raise TelemetryFormatError(
                            "JSON event exceeds the configured per-record byte limit"
                        )
                    event, remainder = _decode_value(
                        text_stream,
                        prefix,
                        maximum_record_bytes=self._maximum_record_bytes,
                        maximum_depth=self._maximum_depth,
                        position="index 0",
                    )
                    _validate_event(
                        event,
                        position="index 0",
                        maximum_depth=self._maximum_depth,
                    )
                    _require_only_whitespace(text_stream, remainder)
                    count = 1
                    container = "json_object"
        except UnicodeDecodeError as exc:
            raise TelemetryFormatError("JSON telemetry must use UTF-8 text encoding") from exc
        except OSError as exc:
            raise TelemetryFormatError("unable to read staged JSON telemetry") from exc
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
