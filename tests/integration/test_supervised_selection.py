"""Validation comparison integrates train-only tuning with explicit selection policy."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from aegishunt.ml.supervised.config import SupervisedTrainingConfig
from aegishunt.ml.supervised.data import SupervisedDatasetGate
from aegishunt.ml.supervised.selection import (
    FittedCandidate,
    evaluate_candidates,
    select_main_candidate,
    select_portable_demo_candidate,
)
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


def test_zero_brier_wins_candidate_tie_and_missing_brier_ranks_last(
    tmp_path: Path,
) -> None:
    data_root, report_root = build_phase4_bundle(tmp_path)
    config = SupervisedTrainingConfig.load(TRAINING_CONFIG_PATH)
    data = SupervisedDatasetGate(data_root, report_root).load_training_validation(
        cv_folds=config.cv_folds
    )
    base = evaluate_candidates(data, config)[0]

    def with_brier(algorithm: str, value: float | None) -> FittedCandidate:
        metrics = base.result.validation_metrics.model_copy(update={"brier_score": value})
        result = base.result.model_copy(
            update={"algorithm": algorithm, "validation_metrics": metrics}
        )
        return replace(base, result=result)

    zero = with_brier("zero-brier", 0.0)
    positive = with_brier("positive-brier", 0.2)
    missing = with_brier("missing-brier", None)

    assert select_main_candidate((positive, zero)).result.algorithm == "zero-brier"
    assert select_main_candidate((missing, zero)).result.algorithm == "zero-brier"
    assert select_main_candidate((zero, positive, missing)).result.algorithm == "zero-brier"


def test_portable_demo_selection_ignores_host_dependent_operational_ties(
    tmp_path: Path,
) -> None:
    data_root, report_root = build_phase4_bundle(tmp_path)
    config = SupervisedTrainingConfig.load(TRAINING_CONFIG_PATH)
    data = SupervisedDatasetGate(data_root, report_root).load_training_validation(
        cv_folds=config.cv_folds
    )
    base = evaluate_candidates(data, config)[0]

    def with_operational_evidence(
        algorithm: str,
        *,
        latency_ms: float,
        size_bytes: int,
    ) -> FittedCandidate:
        operational = base.result.operational_metrics.model_copy(
            update={
                "per_sample_latency_p50_ms": latency_ms,
                "serialized_size_bytes": size_bytes,
            }
        )
        result = base.result.model_copy(
            update={
                "algorithm": algorithm,
                "operational_metrics": operational,
            }
        )
        return replace(base, result=result)

    random_forest = with_operational_evidence(
        "random_forest",
        latency_ms=10.0,
        size_bytes=2_000_000,
    )
    histogram = with_operational_evidence(
        "hist_gradient_boosting",
        latency_ms=0.1,
        size_bytes=1_000,
    )

    assert (
        select_main_candidate((random_forest, histogram)).result.algorithm
        == "hist_gradient_boosting"
    )
    assert (
        select_portable_demo_candidate((random_forest, histogram)).result.algorithm
        == "random_forest"
    )
