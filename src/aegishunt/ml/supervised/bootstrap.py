"""Deterministic group-aware confidence intervals for frozen evaluation."""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray

from aegishunt.ml.supervised.contracts import ConfidenceInterval
from aegishunt.ml.supervised.errors import EvaluationError
from aegishunt.ml.supervised.metrics import evaluate_binary_classification

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
    "false_positive_rate",
    "false_negative_rate",
)


def group_bootstrap_intervals(
    labels: NDArray[np.int64],
    predictions: NDArray[np.int64],
    probabilities: NDArray[np.float64],
    groups: NDArray[np.str_],
    *,
    iterations: int,
    random_seed: int,
) -> dict[str, ConfidenceInterval]:
    """Resample complete groups with replacement and retain valid metric draws."""

    if iterations < 1_000:
        raise EvaluationError("confidence intervals require at least 1,000 iterations")
    unique_groups = tuple(sorted(set(groups.tolist())))
    if not unique_groups:
        raise EvaluationError("group-aware bootstrap requires groups")
    group_indices = {
        group: np.flatnonzero(groups == group).astype(np.int64) for group in unique_groups
    }
    random = np.random.default_rng(random_seed)
    samples: dict[str, list[float]] = {name: [] for name in _CI_METRICS}
    for _ in range(iterations):
        selected = random.choice(unique_groups, size=len(unique_groups), replace=True)
        indices = np.concatenate([group_indices[str(group)] for group in selected])
        metrics = evaluate_binary_classification(
            labels[indices],
            predictions[indices],
            probabilities[indices],
        )
        for name in _CI_METRICS:
            value = getattr(metrics, name)
            if value is not None:
                samples[name].append(float(value))
    intervals: dict[str, ConfidenceInterval] = {}
    for name, values in samples.items():
        if not values:
            continue
        intervals[name] = ConfidenceInterval(
            lower=float(np.percentile(values, 2.5)),
            upper=float(np.percentile(values, 97.5)),
            successful_iterations=len(values),
        )
    return intervals
