"""Validation-only benign-FPR-constrained anomaly threshold selection."""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray

from aegishunt.ml.anomaly.contracts import ThresholdResult
from aegishunt.ml.anomaly.errors import AnomalyEvaluationError
from aegishunt.ml.anomaly.metrics import evaluate_anomaly_metrics, group_stability


def evaluate_thresholds(
    labels: NDArray[np.int64],
    normalized_scores: NDArray[np.float64],
    groups: NDArray[np.str_],
    *,
    candidates: tuple[float, ...],
    false_positive_rate_limit: float,
) -> tuple[ThresholdResult, ...]:
    if not candidates:
        raise AnomalyEvaluationError("threshold candidate set cannot be empty")
    if labels.shape != normalized_scores.shape or groups.shape != labels.shape:
        raise AnomalyEvaluationError("threshold evidence must be aligned")
    return tuple(
        ThresholdResult(
            threshold=threshold,
            metrics=(metrics := evaluate_anomaly_metrics(
                labels,
                (normalized_scores >= threshold).astype(np.int64),
                normalized_scores,
            )),
            group_stability=group_stability(
                labels,
                (normalized_scores >= threshold).astype(np.int64),
                groups,
            ),
            satisfies_fpr_limit=(
                metrics.benign_false_positive_rate <= false_positive_rate_limit
            ),
        )
        for threshold in candidates
    )


def select_threshold(results: tuple[ThresholdResult, ...]) -> ThresholdResult:
    """Choose deterministically without access to frozen-test evidence."""

    if not results:
        raise AnomalyEvaluationError("threshold results cannot be empty")
    eligible = tuple(item for item in results if item.satisfies_fpr_limit)
    pool = eligible or results

    def key(item: ThresholdResult) -> tuple[float, ...]:
        pr_auc = item.metrics.pr_auc if item.metrics.pr_auc is not None else -1.0
        return (
            item.metrics.f1,
            item.metrics.recall,
            pr_auc,
            item.metrics.balanced_accuracy,
            -item.metrics.benign_false_positive_rate,
            -item.group_stability.benign_fpr_standard_deviation,
            -item.threshold,
        )

    return max(pool, key=key)
