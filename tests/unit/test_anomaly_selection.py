"""Isolation Forest selection, threshold, LOF, and bootstrap tests."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

from aegishunt.ml.anomaly.bootstrap import group_bootstrap_intervals
from aegishunt.ml.anomaly.config import AnomalyTrainingConfig
from aegishunt.ml.anomaly.contracts import GroupStability
from aegishunt.ml.anomaly.data import AnomalyDatasetGate
from aegishunt.ml.anomaly.errors import AnomalyEvaluationError
from aegishunt.ml.anomaly.selection import (
    evaluate_isolation_forest_candidates,
    evaluate_lof_comparator,
    one_class_svm_status,
    select_production_candidate,
)
from aegishunt.ml.anomaly.thresholding import evaluate_thresholds, select_threshold
from tests.fixtures.anomaly import ANOMALY_CONFIG_PATH
from tests.fixtures.supervised import build_phase4_bundle


def _data(tmp_path: Path) -> tuple[object, AnomalyTrainingConfig]:
    data_root, report_root = build_phase4_bundle(tmp_path)
    config = AnomalyTrainingConfig.load(ANOMALY_CONFIG_PATH)
    data = AnomalyDatasetGate(data_root, report_root).load_training_validation(
        minimum_benign_groups=config.minimum_benign_groups
    )
    return data, config


def test_threshold_selection_enforces_fpr_then_uses_validation_metrics() -> None:
    labels = np.asarray([0, 0, 1, 1], dtype=np.int64)
    scores = np.asarray([0.1, 0.8, 0.7, 0.9], dtype=np.float64)
    groups = np.asarray(["b1", "b2", "a1", "a2"], dtype=np.str_)
    results = evaluate_thresholds(
        labels,
        scores,
        groups,
        candidates=(0.5, 0.85, 0.95),
        false_positive_rate_limit=0.0,
    )
    selected = select_threshold(results)

    assert selected.threshold == 0.85
    assert selected.satisfies_fpr_limit is True
    assert selected.metrics.benign_false_positive_rate == 0.0
    assert selected.metrics.recall == 0.5


def test_threshold_selection_is_deterministic() -> None:
    labels = np.asarray([0, 0, 1, 1], dtype=np.int64)
    scores = np.asarray([0.1, 0.2, 0.8, 0.9], dtype=np.float64)
    groups = np.asarray(["b", "b", "a", "a"], dtype=np.str_)
    first = evaluate_thresholds(
        labels, scores, groups, candidates=(0.5, 0.7), false_positive_rate_limit=0.1
    )
    second = evaluate_thresholds(
        labels, scores, groups, candidates=(0.5, 0.7), false_positive_rate_limit=0.1
    )

    assert first == second
    assert select_threshold(first) == select_threshold(second)


def test_empty_threshold_candidates_are_rejected() -> None:
    with pytest.raises(AnomalyEvaluationError, match="cannot be empty"):
        evaluate_thresholds(
            np.asarray([0], dtype=np.int64),
            np.asarray([0.0], dtype=np.float64),
            np.asarray(["g"], dtype=np.str_),
            candidates=(),
            false_positive_rate_limit=0.1,
        )


def test_isolation_candidates_fit_benign_only_and_select_deterministically(
    tmp_path: Path,
) -> None:
    data, config = _data(tmp_path)
    assert hasattr(data, "benign_train")
    evaluated = evaluate_isolation_forest_candidates(data, config)  # type: ignore[arg-type]
    selected = select_production_candidate(evaluated.fitted)
    repeated = evaluate_isolation_forest_candidates(data, config)  # type: ignore[arg-type]
    selected_repeated = select_production_candidate(repeated.fitted)

    assert len(evaluated.results) == 3
    assert all(item.status == "passed" for item in evaluated.results)
    assert selected.estimator.named_steps["scale"].n_samples_seen_ == 10
    assert selected.estimator.named_steps["model"].max_samples_ == 10
    assert selected.result.candidate_id == selected_repeated.result.candidate_id
    assert selected.result.selected_threshold == selected_repeated.result.selected_threshold
    assert selected.result.validation_metrics == selected_repeated.result.validation_metrics
    assert selected.result.normalizer == selected_repeated.result.normalizer


def test_lof_is_novelty_mode_offline_only_and_ocsvm_is_truthful(tmp_path: Path) -> None:
    data, config = _data(tmp_path)
    lof = evaluate_lof_comparator(data, config)  # type: ignore[arg-type]
    ocsvm = one_class_svm_status(config)

    assert lof.status == "passed"
    assert lof.production_eligible is False
    assert lof.hyperparameters["novelty"] is True
    assert lof.validation_metrics is not None
    assert ocsvm.status == "not_implemented"
    assert ocsvm.production_eligible is False


def test_lof_reports_insufficient_neighbor_failure(tmp_path: Path) -> None:
    data, config = _data(tmp_path)
    oversized = config.model_copy(
        update={"lof": config.lof.model_copy(update={"n_neighbors": 10})}
    )
    result = evaluate_lof_comparator(data, oversized)  # type: ignore[arg-type]

    assert result.status == "failed"
    assert result.failure_code == "INSUFFICIENT_BENIGN_NEIGHBORS"


def test_group_bootstrap_is_deterministic_and_requires_1000_draws() -> None:
    labels = np.asarray([0, 0, 1, 1], dtype=np.int64)
    predictions = np.asarray([0, 1, 1, 1], dtype=np.int64)
    scores = np.asarray([0.1, 0.7, 0.8, 0.9], dtype=np.float64)
    groups = np.asarray(["g1", "g1", "g2", "g2"], dtype=np.str_)
    first = group_bootstrap_intervals(
        labels, predictions, scores, groups, iterations=1000, random_seed=61
    )
    second = group_bootstrap_intervals(
        labels, predictions, scores, groups, iterations=1000, random_seed=61
    )

    assert first == second
    assert first["f1"].successful_iterations == 1000
    with pytest.raises(AnomalyEvaluationError, match="1,000"):
        group_bootstrap_intervals(
            labels, predictions, scores, groups, iterations=999, random_seed=61
        )


def test_group_stability_contract_rejects_invalid_values() -> None:
    with pytest.raises(ValueError):
        GroupStability(
            group_count=0,
            benign_fpr_mean=0.0,
            benign_fpr_standard_deviation=0.0,
            anomaly_recall_mean=0.0,
            anomaly_recall_standard_deviation=0.0,
            groups_without_benign=0,
            groups_without_anomaly=0,
        )
