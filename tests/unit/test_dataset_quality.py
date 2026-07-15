"""Quality, duplicate, feature-statistics, and class-distribution tests."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest
from pydantic import ValidationError

from aegishunt.datasets.errors import DatasetQualityError
from aegishunt.datasets.quality import (
    analyze_quality,
    write_class_distribution,
    write_feature_statistics,
)
from aegishunt.datasets.schemas import CanonicalDatasetRow, CanonicalFeatureVector
from aegishunt.flows.registry import FEATURE_SCHEMA_VERSION, feature_names
from tests.fixtures.datasets import demo_rows


def _replace_row(
    row: CanonicalDatasetRow,
    *,
    record_id: str | None = None,
    feature_values: tuple[float, ...] | None = None,
    labels_from: CanonicalDatasetRow | None = None,
    observed_at_missing: bool = False,
) -> CanonicalDatasetRow:
    payload = row.model_dump(mode="python")
    if record_id is not None:
        payload["metadata"]["record_id"] = record_id
    if feature_values is not None:
        payload["features"]["values"] = feature_values
    if labels_from is not None:
        payload["labels"] = labels_from.labels.model_dump(mode="python")
    if observed_at_missing:
        payload["metadata"]["observed_at"] = None
    return CanonicalDatasetRow.model_validate(payload)


def test_demo_quality_reports_schema_classes_and_constant_features() -> None:
    rows = demo_rows()

    report = analyze_quality(rows, near_duplicate_tolerance=1e-6)

    assert report.status == "pass"
    assert report.row_count == 48
    assert report.group_count == 24
    assert all(report.missing_counts[f"features.{name}"] == 0 for name in feature_names())
    assert report.binary_class_distribution == {"0": 18, "1": 30}
    assert report.binary_class_percentages == {"0": 0.375, "1": 0.625}
    assert sum(report.attack_family_percentages.values()) == pytest.approx(1.0)
    assert report.conflicting_label_fingerprint_count == 0
    assert report.invalid_features == ()
    assert "urg_count" in report.constant_features
    assert "urg_count" in report.all_zero_features


def test_quality_detects_exact_feature_conflicting_and_near_duplicates() -> None:
    rows = list(demo_rows()[:3])
    exact = rows[0]
    feature_duplicate = _replace_row(rows[0], record_id="new-record")
    attack_row = next(row for row in demo_rows() if row.labels.binary_label == 1)
    conflict = _replace_row(
        rows[0],
        record_id="conflicting-record",
        labels_from=attack_row,
    )
    values = list(rows[1].features.values)
    rate_index = feature_names().index("bytes_per_second")
    values[rate_index] += 0.0000001
    near = _replace_row(rows[1], record_id="near-record", feature_values=tuple(values))

    report = analyze_quality(
        (*rows, exact, feature_duplicate, conflict, near),
        near_duplicate_tolerance=1e-6,
    )

    assert report.status == "fail"
    assert report.exact_duplicate_count >= 1
    assert report.feature_duplicate_count >= 2
    assert report.conflicting_label_fingerprint_count == 1
    assert report.provenance_duplicate_count >= 2
    assert report.near_duplicate_count >= 1
    assert any(finding.code == "Q-CONFLICTING-LABELS" for finding in report.findings)


def test_quality_missing_timestamp_fails_without_imputation() -> None:
    row = _replace_row(demo_rows()[0], observed_at_missing=True)
    report = analyze_quality((row,), near_duplicate_tolerance=1e-6)

    assert report.status == "fail"
    assert report.missing_counts["metadata.observed_at"] == 1


def test_quality_rejects_duplicate_canonical_record_ids() -> None:
    rows = demo_rows()
    duplicate_id = _replace_row(rows[1], record_id=rows[0].metadata.record_id)

    report = analyze_quality((rows[0], duplicate_id), near_duplicate_tolerance=1e-6)

    assert report.status == "fail"
    assert report.duplicate_record_id_count == 1
    assert any(finding.code == "Q-DUPLICATE-RECORD-ID" for finding in report.findings)


def test_quality_and_feature_vector_reject_empty_or_invalid_values() -> None:
    with pytest.raises(DatasetQualityError, match="at least one"):
        analyze_quality((), near_duplicate_tolerance=1e-6)

    row = demo_rows()[0]
    values = list(row.features.values)
    values[0] = 1.5
    with pytest.raises(ValidationError, match="integer-valued"):
        CanonicalFeatureVector(
            schema_version=FEATURE_SCHEMA_VERSION,
            names=feature_names(),
            values=tuple(values),
        )


def test_statistics_and_class_distribution_outputs_are_complete(tmp_path: Path) -> None:
    rows = demo_rows()
    feature_path = tmp_path / "feature_statistics.csv"
    class_path = tmp_path / "class_distribution.csv"

    write_feature_statistics(rows, feature_path)
    write_class_distribution({"all": rows}, class_path)

    with feature_path.open(encoding="utf-8", newline="") as source:
        feature_records = list(csv.DictReader(source))
    with class_path.open(encoding="utf-8", newline="") as source:
        class_records = list(csv.DictReader(source))
    assert len(feature_records) == len(feature_names())
    assert feature_records[0]["feature_schema_version"] == FEATURE_SCHEMA_VERSION
    assert all(record["finite_status"] == "finite" for record in feature_records)
    assert {record["distribution_type"] for record in class_records} == {
        "binary",
        "attack_family",
    }
    with pytest.raises(DatasetQualityError, match="already exists"):
        write_feature_statistics(rows, feature_path)
