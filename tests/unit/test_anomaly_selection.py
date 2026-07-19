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
    evaluate_lof_candidate,
    evaluate_lof_comparator,
    one_class_svm_status,
    select_production_candidate,
)
from aegishunt.ml.anomaly.thresholding import evaluate_thresholds, select_threshold
from tests.fixtures.anomaly import (
    ANOMALY_CONFIG_PATH,
    CORRECTIVE_CONFIG_PATH,
    LOF_CANDIDATE_CONFIG_PATH,
    anomaly_corrective_service,
    anomaly_lof_candidate_service,
)
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


def test_threshold_selection_prefers_compliant_anomaly_utility_over_lower_fpr() -> None:
    labels = np.asarray([0, 0, 0, 0, 1, 1, 1, 1], dtype=np.int64)
    scores = np.asarray([0.1, 0.2, 0.3, 0.75, 0.72, 0.82, 0.91, 0.93], dtype=np.float64)
    groups = np.asarray(["b1", "b2", "b3", "b4", "a1", "a2", "a3", "a4"])
    results = evaluate_thresholds(
        labels,
        scores,
        groups,
        candidates=(0.7, 0.9, 0.95),
        false_positive_rate_limit=0.25,
    )

    selected = select_threshold(results)
    zero_utility = next(item for item in results if item.threshold == 0.95)

    assert zero_utility.metrics.benign_false_positive_rate == 0.0
    assert zero_utility.metrics.recall == 0.0
    assert selected.threshold == 0.7
    assert selected.metrics.benign_false_positive_rate == 0.25
    assert selected.metrics.f1 > zero_utility.metrics.f1


@pytest.mark.parametrize("invalid", (None, float("nan"), float("inf"), float("-inf")))
def test_threshold_selection_rejects_missing_or_nonfinite_policy(invalid: float | None) -> None:
    with pytest.raises(AnomalyEvaluationError, match="numeric|finite"):
        evaluate_thresholds(
            np.asarray([0, 1], dtype=np.int64),
            np.asarray([0.1, 0.9], dtype=np.float64),
            np.asarray(["b", "a"], dtype=np.str_),
            candidates=(invalid,),  # type: ignore[arg-type]
            false_positive_rate_limit=0.25,
        )


def test_empty_threshold_candidates_are_rejected() -> None:
    with pytest.raises(AnomalyEvaluationError, match="cannot be empty"):
        evaluate_thresholds(
            np.asarray([0], dtype=np.int64),
            np.asarray([0.0], dtype=np.float64),
            np.asarray(["g"], dtype=np.str_),
            candidates=(),
            false_positive_rate_limit=0.1,
        )


def test_threshold_selection_fails_closed_when_fpr_limit_is_impossible() -> None:
    results = evaluate_thresholds(
        np.asarray([0, 0, 1], dtype=np.int64),
        np.asarray([0.9, 0.95, 0.99], dtype=np.float64),
        np.asarray(["b1", "b2", "a1"], dtype=np.str_),
        candidates=(0.5, 0.8),
        false_positive_rate_limit=0.0,
    )

    assert not any(item.satisfies_fpr_limit for item in results)
    with pytest.raises(AnomalyEvaluationError, match="no validation threshold"):
        select_threshold(results)


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


def test_corrective_matrix_has_one_deterministic_validation_selection(
    tmp_path: Path,
) -> None:
    _, data_root, report_root, _, _ = anomaly_corrective_service(tmp_path)
    config = AnomalyTrainingConfig.load(CORRECTIVE_CONFIG_PATH)
    data = AnomalyDatasetGate(data_root, report_root).load_training_validation(
        minimum_benign_groups=config.minimum_benign_groups
    )
    evaluated = evaluate_isolation_forest_candidates(data, config)
    selected = select_production_candidate(
        evaluated.fitted,
        selection_policy_version=config.selection_policy_version,
    )
    repeated = select_production_candidate(
        tuple(reversed(evaluated.fitted)),
        selection_policy_version=config.selection_policy_version,
    )

    assert len(evaluated.results) == 24
    assert selected.result.candidate_id == (
        "corrective-iforest-128-bootstrap--benign_training_quantile_cdf"
    )
    assert repeated.result.candidate_id == selected.result.candidate_id
    assert selected.result.selected_threshold == 0.85
    assert selected.result.validation_metrics is not None
    assert selected.result.validation_metrics.benign_false_positive_rate == 0.25
    assert selected.result.validation_metrics.recall == pytest.approx(1 / 3)
    assert selected.result.validation_metrics.f1 == pytest.approx(4 / 9)
    failed = next(
        item
        for item in evaluated.results
        if item.candidate_id.endswith("feature-50--robust_percentile_scaling")
    )
    assert failed.status == "failed"
    assert failed.failure_code == "NO_FPR_COMPLIANT_THRESHOLD"
    assert len(failed.threshold_results) == len(config.threshold_candidates)


def test_lof_is_novelty_mode_offline_only_and_ocsvm_is_truthful(tmp_path: Path) -> None:
    data, config = _data(tmp_path)
    lof = evaluate_lof_comparator(data, config)  # type: ignore[arg-type]
    ocsvm = one_class_svm_status(config)

    assert lof.status == "passed"
    assert lof.production_eligible is False
    assert lof.hyperparameters["novelty"] is True
    assert lof.validation_metrics is not None
    assert lof.preprocessing == "standard_scaler"
    assert lof.raw_score_method == "score_samples"
    assert lof.canonical_score_transform == "negative_raw_score"
    assert lof.normalizer is not None
    assert lof.threshold_policy == "validation_benign_fpr_constrained"
    assert lof.benign_training_rows == 10
    assert lof.benign_training_groups == 5
    assert lof.validation_rows == 10
    assert lof.validation_groups == 5
    assert len(lof.threshold_results) == len(config.threshold_candidates)
    assert lof.validation_metrics.precision == 1.0
    assert lof.validation_metrics.recall == pytest.approx(1 / 3)
    assert lof.validation_metrics.f1 == 0.5
    assert lof.validation_metrics.pr_auc == pytest.approx(0.8083333333333333)
    assert lof.validation_metrics.benign_false_positive_rate == 0.0
    assert lof.validation_metrics.confusion_matrix == ((4, 0), (4, 2))
    assert lof.operational_metrics is not None
    assert lof.operational_metrics.estimator_serialized_size_bytes > 0
    assert lof.operational_metrics.batch_latency_p95_ms >= 0.0
    assert lof.benign_raw_distribution is not None
    assert lof.anomaly_raw_distribution is not None
    assert lof.benign_normalized_distribution is not None
    assert lof.anomaly_normalized_distribution is not None
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


def test_direction_b_selects_registered_lof_without_test_evidence(tmp_path: Path) -> None:
    _, data_root, report_root, _, _ = anomaly_lof_candidate_service(tmp_path)
    config = AnomalyTrainingConfig.load(LOF_CANDIDATE_CONFIG_PATH)
    data = AnomalyDatasetGate(data_root, report_root).load_training_validation(
        minimum_benign_groups=config.minimum_benign_groups
    )
    forests = evaluate_isolation_forest_candidates(data, config)
    lof = evaluate_lof_candidate(data, config)

    assert lof.fitted is not None
    assert lof.comparator.production_eligible is True
    assert lof.fitted.estimator.named_steps["model"].novelty is True
    candidates = (*forests.fitted, lof.fitted)
    selected = select_production_candidate(
        candidates,
        selection_policy_version=config.selection_policy_version,
    )
    repeated = select_production_candidate(
        tuple(reversed(candidates)),
        selection_policy_version=config.selection_policy_version,
    )

    assert selected.result.algorithm == "local_outlier_factor"
    assert selected.result.candidate_id == "lof-novelty-5--benign_training_quantile_cdf"
    assert selected.result.selected_threshold == 0.9
    assert selected.result.validation_metrics is not None
    assert selected.result.validation_metrics.f1 == 0.5
    assert selected.result.validation_metrics.benign_false_positive_rate == 0.0
    assert repeated.result.candidate_id == selected.result.candidate_id


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
