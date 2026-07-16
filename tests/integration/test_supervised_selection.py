"""Validation comparison integrates train-only tuning with explicit selection policy."""

from __future__ import annotations

from pathlib import Path

from aegishunt.ml.supervised.config import SupervisedTrainingConfig
from aegishunt.ml.supervised.data import SupervisedDatasetGate
from aegishunt.ml.supervised.selection import evaluate_candidates, select_main_candidate
from tests.fixtures.supervised import TRAINING_CONFIG_PATH, build_phase4_bundle


def test_all_candidates_are_compared_without_frozen_test_access(tmp_path: Path) -> None:
    data_root, report_root = build_phase4_bundle(tmp_path)
    config = SupervisedTrainingConfig.load(TRAINING_CONFIG_PATH)
    data = SupervisedDatasetGate(data_root, report_root).load_training_validation(
        cv_folds=config.cv_folds
    )

    candidates = evaluate_candidates(data, config)
    selected = select_main_candidate(candidates)

    assert {candidate.result.algorithm for candidate in candidates} == {
        "dummy",
        "logistic_regression",
        "decision_tree",
        "random_forest",
        "hist_gradient_boosting",
    }
    assert selected in candidates
    assert selected.result.validation_metrics.macro_f1 == max(
        candidate.result.validation_metrics.macro_f1 for candidate in candidates
    )
    assert all(candidate.tuning_results for candidate in candidates)
    assert all(
        not fold.evidence.group_overlap
        for candidate in candidates
        for tuning in candidate.tuning_results
        for fold in tuning.folds
    )
    assert all(
        candidate.result.operational_metrics.deterministic_predictions
        for candidate in candidates
    )
