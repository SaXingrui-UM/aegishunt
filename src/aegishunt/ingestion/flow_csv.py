"""Canonical flow-CSV contract validation without Phase 3 persistence."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import cast
from uuid import UUID

from pydantic import JsonValue, ValidationError

from aegishunt.ingestion.base import FilePolicy, TelemetryIngestor
from aegishunt.ingestion.errors import TelemetryFormatError
from aegishunt.ingestion.schemas import IngestionInspection
from aegishunt.schemas.enums import SourceType
from aegishunt.schemas.telemetry import NetworkFlow

REQUIRED_COLUMNS = frozenset(
    {
        "first_seen",
        "last_seen",
        "duration",
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "protocol",
        "forward_packet_count",
        "backward_packet_count",
        "forward_bytes",
        "backward_bytes",
    }
)
OPTIONAL_COLUMNS = frozenset({"ground_truth_label", "attack_family"})
_VALIDATION_SOURCE_ID = UUID(int=0)


class FlowCsvIngestor(TelemetryIngestor):
    """Validate canonical CSV rows while leaving flow storage to Phase 3."""

    source_type = SourceType.FLOW_CSV
    policy = FilePolicy(
        extensions=frozenset({".csv"}),
        content_types=frozenset(
            {
                "application/csv",
                "application/vnd.ms-excel",
                "text/csv",
                "text/plain",
            }
        ),
    )

    def inspect(self, path: Path, *, max_records: int) -> IngestionInspection:
        try:
            with path.open("r", encoding="utf-8-sig", newline="") as stream:
                reader = csv.DictReader(stream)
                columns = reader.fieldnames
                if columns is None:
                    raise TelemetryFormatError("flow CSV is missing a header row")
                normalized = [column.strip() for column in columns]
                if any(not column for column in normalized) or len(set(normalized)) != len(
                    normalized
                ):
                    raise TelemetryFormatError("flow CSV headers must be non-empty and unique")
                present = set(normalized)
                missing = sorted(REQUIRED_COLUMNS - present)
                unexpected = sorted(present - REQUIRED_COLUMNS - OPTIONAL_COLUMNS)
                if missing:
                    raise TelemetryFormatError(
                        f"flow CSV is missing required columns: {', '.join(missing)}"
                    )
                if unexpected:
                    raise TelemetryFormatError(
                        f"flow CSV contains unsupported columns: {', '.join(unexpected)}"
                    )

                count = 0
                for row_number, row in enumerate(reader, start=2):
                    if None in row:
                        raise TelemetryFormatError(
                            f"flow CSV row {row_number} contains more fields than its header"
                        )
                    values = {key.strip(): value for key, value in row.items() if key is not None}
                    if all(value is None or not value.strip() for value in values.values()):
                        raise TelemetryFormatError(f"flow CSV row {row_number} is blank")
                    payload: dict[str, object] = {
                        **values,
                        "source_id": _VALIDATION_SOURCE_ID,
                        "capture_session_id": "phase-2-contract-validation",
                    }
                    for optional in OPTIONAL_COLUMNS:
                        if payload.get(optional) == "":
                            payload[optional] = None
                    for port in ("source_port", "destination_port"):
                        if payload.get(port) == "":
                            payload[port] = None
                    try:
                        NetworkFlow.model_validate(payload)
                    except ValidationError as exc:
                        fields = sorted({str(error["loc"][0]) for error in exc.errors()})
                        raise TelemetryFormatError(
                            f"flow CSV row {row_number} failed validation for: "
                            f"{', '.join(fields)}"
                        ) from exc
                    count += 1
                    if count > max_records:
                        raise TelemetryFormatError(
                            "flow CSV contains more than the configured "
                            f"{max_records} record limit"
                        )
        except UnicodeDecodeError as exc:
            raise TelemetryFormatError("flow CSV must use UTF-8 text encoding") from exc
        except csv.Error as exc:
            raise TelemetryFormatError("flow CSV is malformed") from exc
        except OSError as exc:
            raise TelemetryFormatError("unable to read staged flow CSV") from exc

        return IngestionInspection(
            records_processed=count,
            metadata={
                "container": "flow_csv",
                "columns": cast(list[JsonValue], normalized),
            },
        )
