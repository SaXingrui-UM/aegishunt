"""Training-reference-only bounded anomaly score normalization."""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray

from aegishunt.ml.anomaly.config import NormalizationStrategy
from aegishunt.ml.anomaly.contracts import ScoreNormalization
from aegishunt.ml.anomaly.errors import AnomalyTrainingError


def fit_score_normalizer(
    canonical_training_scores: NDArray[np.float64],
    *,
    version: str,
    quantile_count: int,
    strategy: NormalizationStrategy = "benign_training_quantile_cdf",
) -> ScoreNormalization:
    """Fit quantile knots only from benign training canonical scores."""

    values = np.asarray(canonical_training_scores, dtype=np.float64)
    if values.ndim != 1 or not len(values) or not np.isfinite(values).all():
        raise AnomalyTrainingError("normalizer reference scores must be finite and non-empty")
    if strategy == "benign_training_quantile_cdf":
        probabilities: NDArray[np.float64] = np.asarray(
            np.linspace(0.0, 1.0, min(quantile_count, len(values))),
            dtype=np.float64,
        )
        quantiles: NDArray[np.float64] = np.asarray(
            np.quantile(values, probabilities, method="linear"),
            dtype=np.float64,
        )
        unique: dict[float, float] = {}
        for score, probability in zip(quantiles, probabilities, strict=True):
            unique[float(score)] = float(probability)
    elif strategy == "smoothed_empirical_cdf":
        scores, counts = np.unique(values, return_counts=True)
        preceding = np.cumsum(counts) - counts
        midranks = (preceding + counts / 2.0) / len(values)
        unique = {
            float(score): float(probability)
            for score, probability in zip(scores, midranks, strict=True)
        }
    elif strategy == "robust_percentile_scaling":
        percentiles = np.asarray(
            np.quantile(values, (0.05, 0.95), method="linear"),
            dtype=np.float64,
        )
        lower = float(percentiles[0])
        upper = float(percentiles[1])
        unique = {lower: 0.0} if lower == upper else {lower: 0.0, upper: 1.0}
    else:
        raise AnomalyTrainingError("unsupported anomaly normalization strategy")
    return ScoreNormalization(
        version=version,
        method=strategy,
        score_direction="higher_is_more_anomalous",
        reference_partition="benign_training",
        canonical_score_knots=tuple(unique),
        normalized_score_knots=tuple(unique.values()),
        clipping="clip_to_unit_interval",
        constant_score_value=0.5,
    )


def normalize_scores(
    canonical_scores: NDArray[np.float64],
    normalizer: ScoreNormalization,
) -> NDArray[np.float64]:
    """Apply the frozen quantile mapping with explicit tail clipping."""

    values = np.asarray(canonical_scores, dtype=np.float64)
    if values.ndim != 1 or not len(values) or not np.isfinite(values).all():
        raise AnomalyTrainingError("canonical scores must be finite and non-empty")
    score_knots = np.asarray(normalizer.canonical_score_knots, dtype=np.float64)
    normalized_knots = np.asarray(normalizer.normalized_score_knots, dtype=np.float64)
    if (
        not len(score_knots)
        or score_knots.shape != normalized_knots.shape
        or not np.isfinite(score_knots).all()
        or not np.isfinite(normalized_knots).all()
        or np.any(np.diff(score_knots) <= 0.0)
        or np.any(np.diff(normalized_knots) < 0.0)
    ):
        raise AnomalyTrainingError("saved score-normalization contract is invalid")
    if len(score_knots) == 1:
        result = np.where(
            values < score_knots[0],
            0.0,
            np.where(values > score_knots[0], 1.0, normalizer.constant_score_value),
        )
    else:
        result = np.interp(values, score_knots, normalized_knots, left=0.0, right=1.0)
    bounded = np.clip(np.asarray(result, dtype=np.float64), 0.0, 1.0)
    if not np.isfinite(bounded).all():
        raise AnomalyTrainingError("normalized anomaly scores are not finite")
    return bounded
