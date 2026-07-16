"""Numerically explicit classification metrics for folds and final reports."""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np
from numpy.typing import NDArray
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    precision_score,
    recall_score,
    roc_auc_score,
)

from aegishunt.ml.supervised.contracts import ClassificationMetrics, PerClassMetrics
from aegishunt.ml.supervised.errors import EvaluationError


def evaluate_binary_classification(
    labels: Sequence[int] | NDArray[np.integer],
    predictions: Sequence[int] | NDArray[np.integer],
    calibrated_probabilities: Sequence[float] | NDArray[np.floating],
) -> ClassificationMetrics:
    """Compute the declared binary metrics and record unavailable AUC explicitly."""

    y_true = np.asarray(labels, dtype=np.int64)
    y_pred = np.asarray(predictions, dtype=np.int64)
    probabilities = np.asarray(calibrated_probabilities, dtype=np.float64)
    if y_true.ndim != 1 or not len(y_true) or y_pred.shape != y_true.shape:
        raise EvaluationError("classification labels and predictions must be non-empty vectors")
    if probabilities.shape != y_true.shape or not np.isfinite(probabilities).all():
        raise EvaluationError("classification probabilities must be finite and aligned")
    if not set(y_true.tolist()) <= {0, 1} or not set(y_pred.tolist()) <= {0, 1}:
        raise EvaluationError("classification labels must be binary")
    if np.any((probabilities < 0.0) | (probabilities > 1.0)):
        raise EvaluationError("calibrated probabilities must be within zero and one")

    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    true_negative, false_positive, false_negative, true_positive = (
        int(matrix[0, 0]),
        int(matrix[0, 1]),
        int(matrix[1, 0]),
        int(matrix[1, 1]),
    )
    unavailable: list[str] = []
    if len(set(y_true.tolist())) == 2:
        roc_auc: float | None = float(roc_auc_score(y_true, probabilities))
        pr_auc: float | None = float(average_precision_score(y_true, probabilities))
    else:
        roc_auc = None
        pr_auc = None
        unavailable.extend(("roc_auc", "pr_auc"))
    per_precision, per_recall, per_f1, per_support = precision_recall_fscore_support(
        y_true,
        y_pred,
        labels=[0, 1],
        zero_division=0,
    )
    negative_total = true_negative + false_positive
    positive_total = true_positive + false_negative
    if negative_total == 0:
        unavailable.extend(("specificity", "false_positive_rate"))
    if positive_total == 0:
        unavailable.append("false_negative_rate")
    specificity = true_negative / negative_total if negative_total else 0.0
    false_positive_rate = false_positive / negative_total if negative_total else 0.0
    false_negative_rate = false_negative / positive_total if positive_total else 0.0
    sensitivity = true_positive / positive_total if positive_total else 0.0
    balanced_accuracy = (specificity + sensitivity) / 2.0
    mcc_denominator = (
        (true_positive + false_positive)
        * (true_positive + false_negative)
        * (true_negative + false_positive)
        * (true_negative + false_negative)
    ) ** 0.5
    mcc = (
        (true_positive * true_negative - false_positive * false_negative)
        / mcc_denominator
        if mcc_denominator
        else 0.0
    )
    return ClassificationMetrics(
        accuracy=float(accuracy_score(y_true, y_pred)),
        precision=float(precision_score(y_true, y_pred, zero_division=0)),
        recall=float(recall_score(y_true, y_pred, zero_division=0)),
        f1=float(f1_score(y_true, y_pred, zero_division=0)),
        macro_f1=float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        weighted_f1=float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        balanced_accuracy=balanced_accuracy,
        mcc=mcc,
        roc_auc=roc_auc,
        pr_auc=pr_auc,
        specificity=specificity,
        false_positive_rate=false_positive_rate,
        false_negative_rate=false_negative_rate,
        brier_score=float(brier_score_loss(y_true, probabilities)),
        confusion_matrix=((true_negative, false_positive), (false_negative, true_positive)),
        per_class={
            "benign": PerClassMetrics(
                precision=float(per_precision[0]),
                recall=float(per_recall[0]),
                f1=float(per_f1[0]),
                support=int(per_support[0]),
            ),
            "malicious": PerClassMetrics(
                precision=float(per_precision[1]),
                recall=float(per_recall[1]),
                f1=float(per_f1[1]),
                support=int(per_support[1]),
            ),
        },
        unavailable_metrics=tuple(sorted(set(unavailable))),
    )


def metric_summary(
    values: Sequence[ClassificationMetrics],
) -> tuple[dict[str, float | None], dict[str, float | None]]:
    """Return fold mean/std for model-selection metrics."""

    if not values:
        raise EvaluationError("fold metrics cannot be empty")
    names = (
        "accuracy",
        "precision",
        "recall",
        "f1",
        "macro_f1",
        "weighted_f1",
        "balanced_accuracy",
        "mcc",
        "roc_auc",
        "pr_auc",
        "specificity",
        "false_positive_rate",
        "false_negative_rate",
    )
    means: dict[str, float | None] = {}
    standard_deviations: dict[str, float | None] = {}
    for name in names:
        metric_values = [getattr(metric, name) for metric in values]
        if any(value is None for value in metric_values):
            means[name] = None
            standard_deviations[name] = None
            continue
        numeric = np.asarray(metric_values, dtype=np.float64)
        means[name] = float(np.mean(numeric))
        standard_deviations[name] = float(np.std(numeric, ddof=0))
    return means, standard_deviations
