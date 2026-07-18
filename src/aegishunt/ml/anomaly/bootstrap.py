"""Deterministic group-resampled confidence intervals for anomaly metrics."""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray

from aegishunt.ml.anomaly.contracts import ConfidenceInterval
from aegishunt.ml.anomaly.errors import AnomalyEvaluationError
from aegishunt.ml.anomaly.metrics import evaluate_anomaly_metrics

_CI_METRICS = (
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
    "benign_false_positive_rate",
    "anomaly_false_negative_rate",
)


def group_bootstrap_intervals(
    labels: NDArray[np.int64],
    predictions: NDArray[np.int64],
    normalized_scores: NDArray[np.float64],
    groups: NDArray[np.str_],
    *,
    iterations: int,
    random_seed: int,
) -> dict[str, ConfidenceInterval]:
    if iterations < 1_000:
        raise AnomalyEvaluationError("anomaly confidence intervals require 1,000 draws")
    unique_groups = tuple(sorted(set(groups.tolist())))
    if not unique_groups:
        raise AnomalyEvaluationError("anomaly group bootstrap requires groups")
    indices_by_group = {
        group: np.flatnonzero(groups == group).astype(np.int64) for group in unique_groups
    }
    random = np.random.default_rng(random_seed)
    samples: dict[str, list[float]] = {name: [] for name in _CI_METRICS}
    for _ in range(iterations):
        selected = random.choice(unique_groups, size=len(unique_groups), replace=True)
        indices = np.concatenate([indices_by_group[str(group)] for group in selected])
        metrics = evaluate_anomaly_metrics(
            labels[indices], predictions[indices], normalized_scores[indices]
        )
        for name in _CI_METRICS:
            value = getattr(metrics, name)
            if value is not None:
                samples[name].append(float(value))
    return {
        name: ConfidenceInterval(
            lower=float(np.percentile(values, 2.5)),
            upper=float(np.percentile(values, 97.5)),
            successful_iterations=len(values),
        )
        for name, values in samples.items()
        if values
    }
