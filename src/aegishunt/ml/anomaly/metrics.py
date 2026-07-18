"""Numerically explicit anomaly-positive metrics and score summaries."""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np
from numpy.typing import NDArray
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    precision_score,
    recall_score,
    roc_auc_score,
)

from aegishunt.ml.anomaly.contracts import (
    AnomalyClassMetrics,
    AnomalyMetrics,
    GroupStability,
    ScoreDistribution,
)
from aegishunt.ml.anomaly.errors import AnomalyEvaluationError


def evaluate_anomaly_metrics(
    labels: Sequence[int] | NDArray[np.integer],
    predictions: Sequence[int] | NDArray[np.integer],
    normalized_scores: Sequence[float] | NDArray[np.floating],
) -> AnomalyMetrics:
    """Evaluate anomaly/malicious as positive and record undefined metrics."""

    y_true = np.asarray(labels, dtype=np.int64)
    y_pred = np.asarray(predictions, dtype=np.int64)
    scores = np.asarray(normalized_scores, dtype=np.float64)
    if y_true.ndim != 1 or not len(y_true) or y_pred.shape != y_true.shape:
        raise AnomalyEvaluationError("anomaly labels and predictions must be aligned vectors")
    if scores.shape != y_true.shape or not np.isfinite(scores).all():
        raise AnomalyEvaluationError("anomaly scores must be finite and aligned")
    if not set(y_true.tolist()) <= {0, 1} or not set(y_pred.tolist()) <= {0, 1}:
        raise AnomalyEvaluationError("anomaly labels and predictions must be binary")
    if np.any((scores < 0.0) | (scores > 1.0)):
        raise AnomalyEvaluationError("normalized anomaly scores must be within zero and one")

    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = (int(matrix[0, 0]), int(matrix[0, 1]), int(matrix[1, 0]), int(matrix[1, 1]))
    negative_total = tn + fp
    positive_total = tp + fn
    unavailable: list[str] = []
    if tp + fp == 0:
        unavailable.append("precision")
    if positive_total == 0:
        unavailable.extend(("recall", "anomaly_false_negative_rate"))
    if negative_total == 0:
        unavailable.extend(("specificity", "benign_false_positive_rate"))
    if len(set(y_true.tolist())) == 2:
        roc_auc: float | None = float(roc_auc_score(y_true, scores))
        pr_auc: float | None = float(average_precision_score(y_true, scores))
    else:
        roc_auc = None
        pr_auc = None
        unavailable.extend(("roc_auc", "pr_auc"))
    per_precision, per_recall, per_f1, per_support = precision_recall_fscore_support(
        y_true, y_pred, labels=[0, 1], zero_division=0
    )
    specificity = tn / negative_total if negative_total else 0.0
    fpr = fp / negative_total if negative_total else 0.0
    fnr = fn / positive_total if positive_total else 0.0
    sensitivity = tp / positive_total if positive_total else 0.0
    balanced = (specificity + sensitivity) / 2.0
    denominator = ((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)) ** 0.5
    mcc = (tp * tn - fp * fn) / denominator if denominator else 0.0
    return AnomalyMetrics(
        accuracy=float(accuracy_score(y_true, y_pred)),
        precision=float(precision_score(y_true, y_pred, zero_division=0)),
        recall=float(recall_score(y_true, y_pred, zero_division=0)),
        f1=float(f1_score(y_true, y_pred, zero_division=0)),
        macro_f1=float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        weighted_f1=float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        balanced_accuracy=balanced,
        mcc=mcc,
        roc_auc=roc_auc,
        pr_auc=pr_auc,
        specificity=specificity,
        benign_false_positive_rate=fpr,
        anomaly_false_negative_rate=fnr,
        confusion_matrix=((tn, fp), (fn, tp)),
        per_class={
            "benign": AnomalyClassMetrics(
                precision=float(per_precision[0]),
                recall=float(per_recall[0]),
                f1=float(per_f1[0]),
                support=int(per_support[0]),
            ),
            "anomaly": AnomalyClassMetrics(
                precision=float(per_precision[1]),
                recall=float(per_recall[1]),
                f1=float(per_f1[1]),
                support=int(per_support[1]),
            ),
        },
        unavailable_metrics=tuple(sorted(set(unavailable))),
    )


def summarize_scores(values: Sequence[float] | NDArray[np.floating]) -> ScoreDistribution:
    scores = np.asarray(values, dtype=np.float64)
    if scores.ndim != 1 or not len(scores) or not np.isfinite(scores).all():
        raise AnomalyEvaluationError("score distribution requires finite values")
    quantiles: NDArray[np.float64] = np.asarray(
        np.percentile(scores, (5, 25, 50, 75, 95)),
        dtype=np.float64,
    )
    return ScoreDistribution(
        count=len(scores),
        minimum=float(np.min(scores)),
        q05=float(quantiles[0]),
        q25=float(quantiles[1]),
        median=float(quantiles[2]),
        q75=float(quantiles[3]),
        q95=float(quantiles[4]),
        maximum=float(np.max(scores)),
        mean=float(np.mean(scores)),
        standard_deviation=float(np.std(scores, ddof=0)),
    )


def group_stability(
    labels: NDArray[np.int64],
    predictions: NDArray[np.int64],
    groups: NDArray[np.str_],
) -> GroupStability:
    if labels.shape != predictions.shape or groups.shape != labels.shape or not len(labels):
        raise AnomalyEvaluationError("group stability inputs must be aligned and non-empty")
    fprs: list[float] = []
    recalls: list[float] = []
    no_benign = 0
    no_anomaly = 0
    unique_groups = tuple(sorted(set(groups.tolist())))
    for group in unique_groups:
        indices = np.flatnonzero(groups == group)
        y_true = labels[indices]
        y_pred = predictions[indices]
        benign = y_true == 0
        anomaly = y_true == 1
        if np.any(benign):
            fprs.append(float(np.mean(y_pred[benign] == 1)))
        else:
            no_benign += 1
        if np.any(anomaly):
            recalls.append(float(np.mean(y_pred[anomaly] == 1)))
        else:
            no_anomaly += 1
    return GroupStability(
        group_count=len(unique_groups),
        benign_fpr_mean=float(np.mean(fprs)) if fprs else 0.0,
        benign_fpr_standard_deviation=float(np.std(fprs, ddof=0)) if fprs else 0.0,
        anomaly_recall_mean=float(np.mean(recalls)) if recalls else 0.0,
        anomaly_recall_standard_deviation=(float(np.std(recalls, ddof=0)) if recalls else 0.0),
        groups_without_benign=no_benign,
        groups_without_anomaly=no_anomaly,
    )
