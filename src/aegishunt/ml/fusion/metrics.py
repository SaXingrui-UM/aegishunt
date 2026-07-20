"""Generic binary-detection metrics for bounded experimental scores."""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np
from numpy.typing import NDArray

from aegishunt.ml.anomaly.contracts import AnomalyMetrics
from aegishunt.ml.anomaly.metrics import evaluate_anomaly_metrics
from aegishunt.ml.fusion.errors import FusionContractError


def evaluate_scores(
    labels: Sequence[int] | NDArray[np.integer],
    scores: Sequence[float] | NDArray[np.floating],
    *,
    threshold: float,
) -> AnomalyMetrics:
    """Evaluate score semantics without treating the score as a probability."""

    values = np.asarray(scores, dtype=np.float64)
    if not np.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
        raise FusionContractError("evaluation threshold must be finite and bounded")
    if values.ndim != 1 or not len(values) or not np.isfinite(values).all():
        raise FusionContractError("evaluation scores must be a finite non-empty vector")
    if np.any((values < 0.0) | (values > 1.0)):
        raise FusionContractError("evaluation scores must be inside zero and one")
    predictions = (values >= threshold).astype(np.int64)
    return evaluate_anomaly_metrics(labels, predictions, values)


def metric_deltas(
    fusion: AnomalyMetrics,
    baseline: AnomalyMetrics,
) -> dict[str, float | None]:
    """Return explicit fusion-minus-baseline deltas for declared metrics."""

    names = (
        "recall",
        "f1",
        "macro_f1",
        "pr_auc",
        "benign_false_positive_rate",
        "anomaly_false_negative_rate",
    )
    result: dict[str, float | None] = {}
    for name in names:
        fusion_value = getattr(fusion, name)
        baseline_value = getattr(baseline, name)
        result[name] = (
            None
            if fusion_value is None or baseline_value is None
            else float(fusion_value - baseline_value)
        )
    return result
