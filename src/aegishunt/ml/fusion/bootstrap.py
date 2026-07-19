"""Deterministic group-aware confidence and paired-delta intervals."""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray

from aegishunt.ml.fusion.contracts import MetricInterval
from aegishunt.ml.fusion.errors import FusionContractError

_METRICS = (
    "recall",
    "f1",
    "macro_f1",
    "pr_auc",
    "benign_false_positive_rate",
)


def _interval(values: list[float], *, draws: int, unavailable: str) -> MetricInterval:
    if not values:
        return MetricInterval(
            requested_draws=draws,
            successful_draws=0,
            unavailable_reason=unavailable,
        )
    return MetricInterval(
        lower=float(np.percentile(values, 2.5)),
        upper=float(np.percentile(values, 97.5)),
        requested_draws=draws,
        successful_draws=len(values),
    )


def group_bootstrap_intervals(
    labels: NDArray[np.int64],
    scores: NDArray[np.float64],
    groups: NDArray[np.str_],
    *,
    threshold: float,
    draws: int,
    random_seed: int,
) -> dict[str, MetricInterval]:
    """Resample whole groups and retain unavailable metrics as null evidence."""

    unique = _validate_bootstrap(labels, groups, draws)
    _validate_scores(scores, labels)
    random = np.random.default_rng(random_seed)
    samples: dict[str, list[float]] = {name: [] for name in _METRICS}
    for _ in range(draws):
        indices = _sample_indices(unique, groups, random)
        values = _fast_metric_values(labels[indices], scores[indices], threshold)
        for name, value in values.items():
            if value is not None:
                samples[name].append(value)
    return _build_intervals(samples, draws=draws, unavailable="metric unavailable")


def group_bootstrap_delta_intervals(
    labels: NDArray[np.int64],
    fusion_scores: NDArray[np.float64],
    baseline_scores: NDArray[np.float64],
    groups: NDArray[np.str_],
    *,
    fusion_threshold: float,
    baseline_threshold: float,
    draws: int,
    random_seed: int,
) -> dict[str, MetricInterval]:
    """Use paired group resamples for fusion-minus-baseline deltas."""

    unique = _validate_bootstrap(labels, groups, draws)
    _validate_scores(fusion_scores, labels)
    _validate_scores(baseline_scores, labels)
    random = np.random.default_rng(random_seed)
    samples: dict[str, list[float]] = {name: [] for name in _METRICS}
    for _ in range(draws):
        indices = _sample_indices(unique, groups, random)
        fusion = _fast_metric_values(
            labels[indices], fusion_scores[indices], fusion_threshold
        )
        baseline = _fast_metric_values(
            labels[indices], baseline_scores[indices], baseline_threshold
        )
        for name in _METRICS:
            fusion_value = fusion[name]
            baseline_value = baseline[name]
            if fusion_value is not None and baseline_value is not None:
                samples[name].append(float(fusion_value - baseline_value))
    return _build_intervals(samples, draws=draws, unavailable="paired delta unavailable")


def _validate_bootstrap(
    labels: NDArray[np.int64], groups: NDArray[np.str_], draws: int
) -> tuple[str, ...]:
    if draws < 1_000:
        raise FusionContractError("fusion confidence intervals require 1,000 draws")
    if labels.ndim != 1 or labels.shape != groups.shape or not len(labels):
        raise FusionContractError("fusion bootstrap inputs must be aligned")
    unique = tuple(sorted(set(groups.tolist())))
    if len(unique) < 2:
        raise FusionContractError("fusion bootstrap requires at least two groups")
    return unique


def _sample_indices(
    unique: tuple[str, ...],
    groups: NDArray[np.str_],
    random: np.random.Generator,
) -> NDArray[np.int64]:
    by_group = {group: np.flatnonzero(groups == group).astype(np.int64) for group in unique}
    selected = random.choice(unique, size=len(unique), replace=True)
    return np.concatenate([by_group[str(group)] for group in selected])


def _validate_scores(scores: NDArray[np.float64], labels: NDArray[np.int64]) -> None:
    if (
        scores.shape != labels.shape
        or not np.isfinite(scores).all()
        or np.any((scores < 0.0) | (scores > 1.0))
    ):
        raise FusionContractError("fusion bootstrap scores must be finite and bounded")


def _average_precision(labels: NDArray[np.int64], scores: NDArray[np.float64]) -> float | None:
    positives = int(np.sum(labels == 1))
    if positives == 0 or positives == len(labels):
        return None
    order = np.argsort(-scores, kind="mergesort")
    sorted_labels = labels[order]
    sorted_scores = scores[order]
    cumulative_true = np.cumsum(sorted_labels == 1)
    cumulative_false = np.cumsum(sorted_labels == 0)
    boundaries = np.flatnonzero(
        np.r_[sorted_scores[1:] != sorted_scores[:-1], True]
    )
    previous_recall = 0.0
    average_precision = 0.0
    for index in boundaries:
        true_positive = int(cumulative_true[index])
        false_positive = int(cumulative_false[index])
        recall = true_positive / positives
        precision = true_positive / (true_positive + false_positive)
        average_precision += (recall - previous_recall) * precision
        previous_recall = recall
    return average_precision


def _fast_metric_values(
    labels: NDArray[np.int64], scores: NDArray[np.float64], threshold: float
) -> dict[str, float | None]:
    predictions = scores >= threshold
    positives = labels == 1
    negatives = labels == 0
    true_positive = int(np.sum(predictions & positives))
    false_positive = int(np.sum(predictions & negatives))
    false_negative = int(np.sum(~predictions & positives))
    true_negative = int(np.sum(~predictions & negatives))
    positive_total = true_positive + false_negative
    negative_total = true_negative + false_positive
    precision_denominator = true_positive + false_positive
    recall = true_positive / positive_total if positive_total else 0.0
    precision = true_positive / precision_denominator if precision_denominator else 0.0
    f1 = (
        2.0 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    benign_precision_denominator = true_negative + false_negative
    benign_precision = (
        true_negative / benign_precision_denominator if benign_precision_denominator else 0.0
    )
    benign_recall = true_negative / negative_total if negative_total else 0.0
    benign_f1 = (
        2.0 * benign_precision * benign_recall / (benign_precision + benign_recall)
        if benign_precision + benign_recall
        else 0.0
    )
    return {
        "recall": recall,
        "f1": f1,
        "macro_f1": (f1 + benign_f1) / 2.0,
        "pr_auc": _average_precision(labels, scores),
        "benign_false_positive_rate": (
            false_positive / negative_total if negative_total else 0.0
        ),
    }


def _build_intervals(
    samples: dict[str, list[float]], *, draws: int, unavailable: str
) -> dict[str, MetricInterval]:
    return {
        name: _interval(
            values,
            draws=draws,
            unavailable=f"{unavailable} in every group-bootstrap draw",
        )
        for name, values in samples.items()
    }
