"""Deterministic raw-flow CSV to canonical dataset conversion."""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

from pydantic import ValidationError

from aegishunt.datasets.errors import DatasetConversionError
from aegishunt.datasets.io import sha256_file
from aegishunt.datasets.labels import LabelMapper
from aegishunt.datasets.schemas import (
    CANONICAL_SCHEMA_VERSION,
    CONVERSION_VERSION,
    CanonicalDatasetRow,
    CanonicalFeatureVector,
    CanonicalMetadata,
)
from aegishunt.flows.registry import FEATURE_SCHEMA_VERSION, feature_names

METADATA_COLUMNS = (
    "record_id",
    "capture_session_id",
    "scenario_id",
    "group_id",
    "original_row_id",
    "observed_at",
    "original_label",
)


def _required_columns() -> tuple[str, ...]:
    return (*METADATA_COLUMNS, *feature_names())


def convert_flow_csv(
    raw_path: Path,
    *,
    dataset_id: str,
    dataset_version: str,
    label_mapper: LabelMapper,
) -> tuple[CanonicalDatasetRow, ...]:
    """Convert an exact Phase 3 feature export; never fabricate absent features."""

    checksum = sha256_file(raw_path)
    rows: list[CanonicalDatasetRow] = []
    try:
        with raw_path.open(encoding="utf-8-sig", newline="") as source:
            reader = csv.DictReader(source)
            if reader.fieldnames is None:
                raise DatasetConversionError("raw CSV is missing a header")
            normalized_header = tuple(name.strip() for name in reader.fieldnames)
            if normalized_header != _required_columns():
                raise DatasetConversionError(
                    "raw CSV columns must exactly match metadata plus the Phase 3 feature order"
                )
            for row_number, raw in enumerate(reader, start=1):
                try:
                    observed_at = datetime.fromisoformat(raw["observed_at"])
                    values = tuple(float(raw[name]) for name in feature_names())
                    rows.append(
                        CanonicalDatasetRow(
                            canonical_schema_version=CANONICAL_SCHEMA_VERSION,
                            metadata=CanonicalMetadata(
                                dataset_id=dataset_id,
                                dataset_version=dataset_version,
                                record_id=raw["record_id"],
                                source_file=raw_path.name,
                                source_file_checksum=checksum,
                                capture_session_id=raw["capture_session_id"],
                                scenario_id=raw["scenario_id"],
                                group_id=raw["group_id"],
                                original_row_id=raw["original_row_id"],
                                observed_at=observed_at,
                                provenance={
                                    "adapter": "phase3-feature-csv",
                                    "raw_format": "csv",
                                },
                                conversion_version=CONVERSION_VERSION,
                            ),
                            features=CanonicalFeatureVector(
                                schema_version=FEATURE_SCHEMA_VERSION,
                                names=feature_names(),
                                values=values,
                            ),
                            labels=label_mapper.map(raw["original_label"]),
                        )
                    )
                except (KeyError, TypeError, ValueError, ValidationError) as exc:
                    raise DatasetConversionError(
                        f"raw CSV row cannot be converted at record {row_number}"
                    ) from exc
    except OSError as exc:
        raise DatasetConversionError("unable to read raw CSV") from exc
    if not rows:
        raise DatasetConversionError("raw CSV contains no records")
    return tuple(rows)
