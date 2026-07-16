"""Validation-only deterministic classification-threshold selection."""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray

from aegishunt.ml.supervised.contracts import ThresholdResult
from aegishunt.ml.supervised.errors import TrainingError
from aegishunt.ml.supervised.metrics import evaluate_binary_classification


def select_threshold(
    probabilities: NDArray[np.float64],
    labels: NDArray[np.int64],
    candidates: tuple[float, ...],
) -> tuple[float, tuple[ThresholdResult, ...]]:
    """Maximize validation Macro F1, then recall/FPR with a stable tie break."""

    if not candidates:
        raise TrainingError("threshold candidate list is empty")
    results = tuple(
        ThresholdResult(
            threshold=threshold,
            metrics=evaluate_binary_classification(
                labels,
                (probabilities >= threshold).astype(np.int64),
                probabilities,
            ),
        )
        for threshold in candidates
    )
    selected = max(
        results,
        key=lambda result: (
            result.metrics.macro_f1,
            result.metrics.recall,
            -result.metrics.false_positive_rate,
            -abs(result.threshold - 0.5),
            -result.threshold,
        ),
    )
    return selected.threshold, results
