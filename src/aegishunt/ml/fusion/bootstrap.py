"""Deterministic group-aware confidence and paired-delta intervals."""

from __future__ import annotations

from collections.abc import Callable

import numpy as np
from numpy.typing import NDArray

from aegishunt.ml.fusion.contracts import MetricInterval
from aegishunt.ml.fusion.errors import FusionContractError
from aegishunt.ml.fusion.metrics import evaluate_scores

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

    return _bootstrap(
        labels,
        groups,
        draws=draws,
        random_seed=random_seed,
        evaluator=lambda indices: evaluate_scores(
            labels[indices], scores[indices], threshold=threshold
        ),
    )


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

    def evaluator(indices: NDArray[np.int64]) -> object:
        fusion = evaluate_scores(
            labels[indices], fusion_scores[indices], threshold=fusion_threshold
        )
        baseline = evaluate_scores(
            labels[indices], baseline_scores[indices], threshold=baseline_threshold
        )
        return {
            name: (
                None
                if getattr(fusion, name) is None or getattr(baseline, name) is None
                else float(getattr(fusion, name) - getattr(baseline, name))
            )
            for name in _METRICS
        }

    return _bootstrap_delta(
        labels,
        groups,
        draws=draws,
        random_seed=random_seed,
        evaluator=evaluator,
    )


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


def _bootstrap(
    labels: NDArray[np.int64],
    groups: NDArray[np.str_],
    *,
    draws: int,
    random_seed: int,
    evaluator: Callable[[NDArray[np.int64]], object],
) -> dict[str, MetricInterval]:
    unique = _validate_bootstrap(labels, groups, draws)
    random = np.random.default_rng(random_seed)
    samples: dict[str, list[float]] = {name: [] for name in _METRICS}
    for _ in range(draws):
        metrics = evaluator(_sample_indices(unique, groups, random))
        for name in _METRICS:
            value = getattr(metrics, name)
            if value is not None:
                samples[name].append(float(value))
    return {
        name: _interval(
            values,
            draws=draws,
            unavailable="metric unavailable in every group-bootstrap draw",
        )
        for name, values in samples.items()
    }


def _bootstrap_delta(
    labels: NDArray[np.int64],
    groups: NDArray[np.str_],
    *,
    draws: int,
    random_seed: int,
    evaluator: Callable[[NDArray[np.int64]], object],
) -> dict[str, MetricInterval]:
    unique = _validate_bootstrap(labels, groups, draws)
    random = np.random.default_rng(random_seed)
    samples: dict[str, list[float]] = {name: [] for name in _METRICS}
    for _ in range(draws):
        result = evaluator(_sample_indices(unique, groups, random))
        if not isinstance(result, dict):
            raise FusionContractError("fusion delta evaluator returned invalid evidence")
        for name in _METRICS:
            value = result[name]
            if value is not None:
                samples[name].append(float(value))
    return {
        name: _interval(
            values,
            draws=draws,
            unavailable="paired delta unavailable in every group-bootstrap draw",
        )
        for name, values in samples.items()
    }
