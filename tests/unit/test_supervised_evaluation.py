"""Metric, calibration, and validation-threshold correctness tests."""

from __future__ import annotations

import numpy as np
import pytest

from aegishunt.ml.supervised.calibration import select_calibration
from aegishunt.ml.supervised.config import SupervisedTrainingConfig
from aegishunt.ml.supervised.errors import EvaluationError, TrainingError
from aegishunt.ml.supervised.metrics import (
    evaluate_binary_classification,
    metric_summary,
)
from aegishunt.ml.supervised.thresholding import select_threshold
from tests.fixtures.supervised import TRAINING_CONFIG_PATH


def test_binary_metrics_include_declared_classification_measures() -> None:
    metrics = evaluate_binary_classification(
        [0, 0, 1, 1],
        [0, 1, 1, 0],
        [0.1, 0.7, 0.8, 0.4],
    )

    assert metrics.accuracy == 0.5
    assert metrics.precision == 0.5
    assert metrics.recall == 0.5
    assert metrics.f1 == 0.5
    assert metrics.macro_f1 == 0.5
    assert metrics.weighted_f1 == 0.5
    assert metrics.balanced_accuracy == 0.5
    assert metrics.mcc == 0.0
    assert metrics.roc_auc == 0.75
    assert metrics.pr_auc == pytest.approx(5 / 6)
    assert metrics.false_positive_rate == 0.5
    assert metrics.false_negative_rate == 0.5
    assert metrics.confusion_matrix == ((1, 1), (1, 1))


def test_metrics_record_auc_as_unavailable_for_one_class() -> None:
    metrics = evaluate_binary_classification([0, 0], [0, 0], [0.1, 0.2])

    assert metrics.roc_auc is None
    assert metrics.pr_auc is None
    assert "roc_auc" in metrics.unavailable_metrics
    assert "false_negative_rate" in metrics.unavailable_metrics


def test_metrics_reject_non_finite_probability() -> None:
    with pytest.raises(EvaluationError, match="finite"):
        evaluate_binary_classification([0, 1], [0, 1], [0.1, float("nan")])


def test_metric_summary_uses_population_standard_deviation() -> None:
    lower = evaluate_binary_classification([0, 1], [0, 0], [0.1, 0.4])
    upper = evaluate_binary_classification([0, 1], [0, 1], [0.1, 0.9])

    means, deviations = metric_summary((lower, upper))

    assert means["accuracy"] == 0.75
    assert deviations["accuracy"] == 0.25


def test_calibration_and_threshold_selection_use_validation_evidence() -> None:
    config = SupervisedTrainingConfig.load(TRAINING_CONFIG_PATH)
    labels = np.asarray([0, 0, 0, 0, 1, 1, 1, 1, 1, 1], dtype=np.int64)
    scores = np.asarray([0.1, 0.2, 0.3, 0.4, 0.45, 0.6, 0.7, 0.8, 0.9, 0.95])

    calibrator, calibration_evidence = select_calibration(scores, labels, config)
    probabilities = calibrator.transform(scores)
    threshold, curve = select_threshold(probabilities, labels, config.threshold_candidates)

    assert len(calibration_evidence) == 2
    assert all(result.status == "passed" for result in calibration_evidence)
    assert np.isfinite(probabilities).all()
    assert np.all((probabilities >= 0.0) & (probabilities <= 1.0))
    assert threshold in config.threshold_candidates
    assert len(curve) == len(config.threshold_candidates)


def test_calibration_rejects_single_class_validation() -> None:
    config = SupervisedTrainingConfig.load(TRAINING_CONFIG_PATH)

    with pytest.raises(TrainingError, match="both validation classes"):
        select_calibration(
            np.asarray([0.1, 0.2], dtype=np.float64),
            np.asarray([0, 0], dtype=np.int64),
            config,
        )
