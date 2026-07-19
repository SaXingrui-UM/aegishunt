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
    try:
        candidate_values = np.asarray(candidates, dtype=np.float64)
        fpr_limit = float(false_positive_rate_limit)
    except (TypeError, ValueError) as exc:
        raise AnomalyEvaluationError("anomaly threshold policy must be numeric") from exc
    if (
        not np.isfinite(candidate_values).all()
        or np.any((candidate_values < 0.0) | (candidate_values > 1.0))
        or not np.isfinite(fpr_limit)
        or not 0.0 <= fpr_limit < 1.0
    ):
        raise AnomalyEvaluationError("anomaly threshold policy must be finite and bounded")
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
                metrics.benign_false_positive_rate <= fpr_limit
            ),
        )
        for threshold in candidates
    )


def select_threshold(
    results: tuple[ThresholdResult, ...],
    *,
    policy_version: str = "1.0.0",
) -> ThresholdResult:
    """Choose a compliant threshold deterministically without frozen-test evidence."""

    if not results:
        raise AnomalyEvaluationError("threshold results cannot be empty")
    eligible = tuple(item for item in results if item.satisfies_fpr_limit)
    if not eligible:
        raise AnomalyEvaluationError(
            "no validation threshold satisfies the configured benign FPR limit"
        )

    def key(item: ThresholdResult) -> tuple[float, ...]:
        pr_auc = item.metrics.pr_auc if item.metrics.pr_auc is not None else -1.0
        common = (
            item.metrics.f1,
            item.metrics.recall,
            pr_auc,
            item.metrics.balanced_accuracy,
            -item.metrics.benign_false_positive_rate,
            -item.group_stability.benign_fpr_standard_deviation,
            -item.threshold,
        )
        if policy_version == "1.0.0":
            return common
        if policy_version in {"1.0.1", "2.0.0"}:
            return (float(item.metrics.f1 > 0.0), *common)
        raise AnomalyEvaluationError("unsupported anomaly threshold-selection policy")

    return max(eligible, key=key)
