"""Phase 7 controlled dataset, leakage, timeline, and shift tests."""

import numpy as np

from aegishunt.datasets.labels import LabelMapper
from aegishunt.ml.fusion.dataset import (
    ControlledExperimentDataset,
    build_controlled_experiment_dataset,
    build_parameter_shift_partition,
)
from tests.fixtures.datasets import LABEL_ROOT
from tests.fixtures.fusion import fusion_config


def _dataset() -> ControlledExperimentDataset:
    mapper = LabelMapper.load(LABEL_ROOT / "aegishunt-controlled-demo-v1.yaml")
    return build_controlled_experiment_dataset(fusion_config(), mapper)


def test_controlled_dataset_has_new_identity_quality_and_group_isolation() -> None:
    dataset = _dataset()

    assert dataset.manifest.dataset_id == "aegishunt-phase-07-controlled"
    assert dataset.manifest.row_count == 144
    assert dataset.manifest.group_count == 72
    assert len(dataset.manifest.attack_families) == 5
    assert dataset.manifest.public_benchmark is False
    assert dataset.manifest.historical_frozen_test_reused is False
    assert dataset.manifest.conflicting_label_fingerprint_count == 0
    assert dataset.split_manifest.group_overlap == ()
    assert dataset.split_manifest.source_overlap == ()
    assert dataset.split_manifest.session_overlap == ()
    assert dataset.split_manifest.scenario_overlap == ()
    assert dataset.split_manifest.row_counts == {"early": 48, "middle": 48, "late": 48}
    assert dataset.split_manifest.group_counts == {"early": 24, "middle": 24, "late": 24}


def test_controlled_dataset_is_deterministic_and_temporally_strict() -> None:
    first = _dataset()
    second = _dataset()
    ranges = first.split_manifest.time_ranges

    assert first.manifest.dataset_checksum == second.manifest.dataset_checksum
    assert first.rows == second.rows
    assert ranges["early"][1] < ranges["middle"][0] < ranges["late"][0]
    assert set(first.stage("early").groups).isdisjoint(first.stage("middle").groups)
    assert set(first.stage("middle").groups).isdisjoint(first.stage("late").groups)


def test_leave_one_family_out_removes_family_from_fit_and_selection() -> None:
    dataset = _dataset()
    held_out = "exfiltration"
    train, validation, evaluation = dataset.leave_one_family_out(held_out)

    assert held_out not in set(train.families)
    assert held_out not in set(validation.families)
    assert set(evaluation.families) == {"benign", held_out}
    assert set(train.groups).isdisjoint(validation.groups)
    assert set(train.groups).isdisjoint(evaluation.groups)
    assert set(validation.groups).isdisjoint(evaluation.groups)


def test_parameter_shifts_are_bounded_deterministic_and_use_new_groups() -> None:
    dataset = _dataset()
    baseline = dataset.stage("late")

    for shift in fusion_config().parameter_shifts:
        first = build_parameter_shift_partition(baseline, shift)
        second = build_parameter_shift_partition(baseline, shift)
        assert first.rows == second.rows
        assert set(first.groups).isdisjoint(baseline.groups)
        assert np.isfinite(first.features).all()
        assert first.features.shape == baseline.features.shape
        assert not np.array_equal(first.features, baseline.features)
