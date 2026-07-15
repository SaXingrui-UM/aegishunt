"""Canonical conversion, serialization, and provenance boundary tests."""

from __future__ import annotations

import csv
import hashlib
import json
from datetime import date
from pathlib import Path

import pytest
from pydantic import ValidationError

from aegishunt.datasets.conversion import METADATA_COLUMNS, convert_flow_csv
from aegishunt.datasets.errors import DatasetConversionError
from aegishunt.datasets.io import (
    canonical_row_json,
    read_canonical_jsonl,
    sha256_file,
    write_canonical_jsonl,
)
from aegishunt.datasets.labels import LabelMapper
from aegishunt.datasets.schemas import CanonicalDatasetRow, CanonicalMetadata
from aegishunt.flows.registry import feature_names
from tests.fixtures.datasets import LABEL_ROOT, demo_rows


def _write_raw_csv(
    path: Path,
    *,
    original_label: str = "normal",
    overrides: dict[str, str] | None = None,
    header: tuple[str, ...] | None = None,
) -> Path:
    row = demo_rows()[0]
    payload = {
        "record_id": "provider-row-1",
        "capture_session_id": "capture-001",
        "scenario_id": "scenario-001",
        "group_id": "group-001",
        "original_row_id": "1",
        "observed_at": row.metadata.observed_at.isoformat()
        if row.metadata.observed_at is not None
        else "",
        "original_label": original_label,
        **{
            name: str(row.features.values[index])
            for index, name in enumerate(feature_names())
        },
    }
    payload.update(overrides or {})
    selected_header = header or (*METADATA_COLUMNS, *feature_names())
    with path.open("w", encoding="utf-8", newline="") as destination:
        writer = csv.DictWriter(
            destination,
            fieldnames=selected_header,
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerow(payload)
    return path


def test_exact_phase3_csv_conversion_is_deterministic_and_preserves_source(tmp_path: Path) -> None:
    raw = _write_raw_csv(tmp_path / "raw.csv")
    before = raw.read_bytes()
    mapper = LabelMapper.load(LABEL_ROOT / "aegishunt-controlled-demo-v1.yaml")

    first = convert_flow_csv(
        raw,
        dataset_id="aegishunt-controlled-demo",
        dataset_version="1.0.0",
        label_mapper=mapper,
        source_access_date=date(2026, 1, 1),
    )
    second = convert_flow_csv(
        raw,
        dataset_id="aegishunt-controlled-demo",
        dataset_version="1.0.0",
        label_mapper=mapper,
        source_access_date=date(2026, 1, 1),
    )

    assert first == second
    assert raw.read_bytes() == before
    assert first[0].features.names == feature_names()
    assert first[0].labels.original_label == "normal"
    assert first[0].metadata.source_file == "raw.csv"
    assert first[0].metadata.source_file_checksum == hashlib.sha256(before).hexdigest()
    assert "ground_truth_label" not in first[0].features.names
    assert "source_file" not in first[0].features.names


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"observed_at": "not-a-time"}, "cannot be converted"),
        ({feature_names()[0]: "nan"}, "cannot be converted"),
        ({feature_names()[1]: "inf"}, "cannot be converted"),
    ],
)
def test_conversion_rejects_malformed_or_non_finite_rows(
    tmp_path: Path,
    overrides: dict[str, str],
    message: str,
) -> None:
    raw = _write_raw_csv(tmp_path / "bad.csv", overrides=overrides)
    mapper = LabelMapper.load(LABEL_ROOT / "aegishunt-controlled-demo-v1.yaml")
    with pytest.raises(DatasetConversionError, match=message):
        convert_flow_csv(
            raw,
            dataset_id="aegishunt-controlled-demo",
            dataset_version="1.0.0",
            label_mapper=mapper,
            source_access_date=date(2026, 1, 1),
        )


def test_conversion_rejects_unknown_label_header_mismatch_and_empty_input(tmp_path: Path) -> None:
    mapper = LabelMapper.load(LABEL_ROOT / "aegishunt-controlled-demo-v1.yaml")
    unknown = _write_raw_csv(tmp_path / "unknown.csv", original_label="mystery")
    with pytest.raises(DatasetConversionError, match="unmapped label"):
        convert_flow_csv(
            unknown,
            dataset_id="aegishunt-controlled-demo",
            dataset_version="1.0.0",
            label_mapper=mapper,
            source_access_date=date(2026, 1, 1),
        )

    wrong = _write_raw_csv(tmp_path / "wrong.csv", header=("record_id",))
    with pytest.raises(DatasetConversionError, match="must exactly match"):
        convert_flow_csv(
            wrong,
            dataset_id="aegishunt-controlled-demo",
            dataset_version="1.0.0",
            label_mapper=mapper,
            source_access_date=date(2026, 1, 1),
        )

    empty = tmp_path / "empty.csv"
    empty.write_text(",".join((*METADATA_COLUMNS, *feature_names())) + "\n", encoding="utf-8")
    with pytest.raises(DatasetConversionError, match="no records"):
        convert_flow_csv(
            empty,
            dataset_id="aegishunt-controlled-demo",
            dataset_version="1.0.0",
            label_mapper=mapper,
            source_access_date=date(2026, 1, 1),
        )


def test_conversion_rejects_label_mapping_for_different_dataset(tmp_path: Path) -> None:
    raw = _write_raw_csv(tmp_path / "raw.csv")
    mapper = LabelMapper.load(LABEL_ROOT / "aegishunt-controlled-demo-v1.yaml")

    with pytest.raises(DatasetConversionError, match="does not match conversion input"):
        convert_flow_csv(
            raw,
            dataset_id="different-dataset",
            dataset_version="1.0.0",
            label_mapper=mapper,
            source_access_date=date(2026, 1, 1),
        )


def test_canonical_jsonl_round_trip_is_stable_and_non_overwriting(tmp_path: Path) -> None:
    rows = demo_rows()[:3]
    output = tmp_path / "canonical.jsonl"

    checksum = write_canonical_jsonl(rows, output)
    reopened = read_canonical_jsonl(output)

    assert reopened == rows
    assert checksum == sha256_file(output)
    assert output.read_text(encoding="utf-8").splitlines()[0] == canonical_row_json(rows[0])
    with pytest.raises(DatasetConversionError, match="already exists"):
        write_canonical_jsonl(rows, output)


def test_canonical_reader_rejects_empty_and_malformed_files(tmp_path: Path) -> None:
    empty = tmp_path / "empty.jsonl"
    empty.write_text("\n", encoding="utf-8")
    with pytest.raises(DatasetConversionError, match="empty"):
        read_canonical_jsonl(empty)

    malformed = tmp_path / "malformed.jsonl"
    malformed.write_text(json.dumps({"wrong": True}) + "\n", encoding="utf-8")
    with pytest.raises(DatasetConversionError, match="line 1"):
        read_canonical_jsonl(malformed)


def test_canonical_metadata_rejects_absolute_or_traversal_source_identifiers() -> None:
    row = demo_rows()[0]
    payload = row.metadata.model_dump(mode="python")
    for unsafe in ("/private/data.csv", "../outside.csv"):
        payload["source_file"] = unsafe
        with pytest.raises(ValidationError, match="safe relative"):
            CanonicalMetadata.model_validate(payload)


def test_canonical_schema_rejects_string_features_and_string_binary_labels() -> None:
    payload = demo_rows()[0].model_dump(mode="python")
    values = list(payload["features"]["values"])
    values[0] = "5"
    payload["features"]["values"] = values
    with pytest.raises(ValidationError, match="JSON numbers"):
        CanonicalDatasetRow.model_validate(payload)

    payload = demo_rows()[0].model_dump(mode="python")
    payload["labels"]["binary_label"] = "0"
    with pytest.raises(ValidationError, match="valid integer"):
        CanonicalDatasetRow.model_validate(payload)


def test_canonical_writer_does_not_overwrite_racing_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "canonical.jsonl"

    def racing_link(source: Path, target: Path) -> None:
        del source
        Path(target).write_text("concurrent-writer\n", encoding="utf-8")
        raise FileExistsError

    monkeypatch.setattr("aegishunt.datasets.io.os.link", racing_link)

    with pytest.raises(DatasetConversionError, match="already exists"):
        write_canonical_jsonl(demo_rows()[:1], output)
    assert output.read_text(encoding="utf-8") == "concurrent-writer\n"
