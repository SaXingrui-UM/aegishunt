"""Group-aware split determinism and fail-closed leakage tests."""

from __future__ import annotations

from collections import defaultdict

import pytest

from aegishunt.datasets.errors import DatasetSplitError
from aegishunt.datasets.leakage import analyze_leakage
from aegishunt.datasets.schemas import CanonicalDatasetRow, SplitAssignment
from aegishunt.datasets.split import assignments_json, group_aware_split
from aegishunt.flows.registry import feature_names
from tests.fixtures.datasets import demo_rows


def _split(rows: tuple[CanonicalDatasetRow, ...], seed: int = 4_204):  # type: ignore[no-untyped-def]
    return group_aware_split(
        rows,
        seed=seed,
        train_ratio=0.6,
        validation_ratio=0.2,
        test_ratio=0.2,
    )


def _replace_metadata(row: CanonicalDatasetRow, **updates: str) -> CanonicalDatasetRow:
    payload = row.model_dump(mode="python")
    payload["metadata"].update(updates)
    return CanonicalDatasetRow.model_validate(payload)


def test_group_split_is_deterministic_exclusive_and_frozen() -> None:
    rows = demo_rows()

    first, manifest = _split(rows)
    second, second_manifest = _split(rows)
    different, _ = _split(rows, seed=4_205)

    assert first == second
    assert manifest == second_manifest
    assert assignments_json(first) == assignments_json(second)
    assert assignments_json(first) != assignments_json(different)
    assert manifest.frozen_test is True
    assert manifest.overlap_validation_result == "pass"
    assert sum(manifest.row_counts.values()) == len(rows)
    assert set(manifest.train_groups).isdisjoint(manifest.validation_groups)
    assert set(manifest.train_groups).isdisjoint(manifest.test_groups)
    assert set(manifest.validation_groups).isdisjoint(manifest.test_groups)

    identity_splits: dict[str, set[str]] = defaultdict(set)
    for assignment in first:
        identity_splits[assignment.row.metadata.source_file].add(assignment.split)
    assert all(len(splits) == 1 for splits in identity_splits.values())


def test_split_rejects_insufficient_groups_and_identity_leakage() -> None:
    rows = demo_rows()
    with pytest.raises(DatasetSplitError, match="three independent groups"):
        _split(rows[:2])

    second_group = rows[2]
    leaking = _replace_metadata(second_group, source_file=rows[0].metadata.source_file)
    with pytest.raises(DatasetSplitError, match="source_file is shared"):
        _split((rows[0], leaking, *rows[4:8]))

    with pytest.raises(DatasetSplitError, match="sum to 1.0"):
        group_aware_split(
            rows,
            seed=1,
            train_ratio=0.5,
            validation_ratio=0.3,
            test_ratio=0.3,
        )


def test_clean_demo_passes_formal_leakage_gates() -> None:
    assignments, _ = _split(demo_rows())

    report = analyze_leakage(assignments, near_duplicate_tolerance=1e-6)

    assert report.status == "pass"
    assert report.group_overlap == ()
    assert report.source_file_overlap == ()
    assert report.exact_duplicate_overlap == ()
    assert report.near_duplicate_overlap == ()
    assert report.label_derived_features == ()
    assert report.suspicious_metadata == ()


def test_leakage_detects_group_source_session_scenario_and_duplicate_overlap() -> None:
    assignments, _ = _split(demo_rows())
    first = assignments[0]
    replacement_split = "test" if first.split != "test" else "train"
    tampered = (
        SplitAssignment(split=replacement_split, row=first.row),
        *assignments[1:],
    )

    report = analyze_leakage(tampered, near_duplicate_tolerance=1e-6)

    assert report.status == "fail"
    assert first.row.metadata.group_id in report.group_overlap
    assert first.row.metadata.source_file in report.source_file_overlap
    assert first.row.metadata.capture_session_id in report.session_overlap
    assert first.row.metadata.scenario_id in report.scenario_overlap


def test_leakage_detects_label_derived_feature_and_filename_signal() -> None:
    rows: list[CanonicalDatasetRow] = []
    target_index = feature_names().index("failed_connection_indicator")
    for row in demo_rows():
        payload = row.model_dump(mode="python")
        values = list(payload["features"]["values"])
        values[target_index] = float(row.labels.binary_label)
        payload["features"]["values"] = values
        payload["metadata"]["source_file"] = (
            f"attack-{row.metadata.source_file}"
            if row.labels.binary_label == 1
            else row.metadata.source_file
        )
        if row.labels.binary_label == 1:
            payload["metadata"]["scenario_id"] = f"scan-{row.metadata.scenario_id}"
        rows.append(CanonicalDatasetRow.model_validate(payload))
    assignments, _ = _split(tuple(rows))

    report = analyze_leakage(assignments, near_duplicate_tolerance=1e-6)

    assert report.status == "fail"
    assert "failed_connection_indicator" in report.label_derived_features
    assert report.filename_leakage
    assert any(value.startswith("scenario_id:scan-") for value in report.suspicious_metadata)
