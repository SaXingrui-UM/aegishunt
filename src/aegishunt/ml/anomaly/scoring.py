"""Estimator-independent anomaly score direction contract."""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray
from sklearn.pipeline import Pipeline

from aegishunt.ml.anomaly.errors import AnomalyTrainingError


def raw_score_samples(
    estimator: Pipeline,
    features: NDArray[np.float64],
) -> NDArray[np.float64]:
    """Return the estimator score where larger values are more normal."""

    if features.ndim != 2 or not len(features) or not np.isfinite(features).all():
        raise AnomalyTrainingError("anomaly scoring requires a finite non-empty matrix")
    try:
        values = np.asarray(estimator.score_samples(features), dtype=np.float64)
    except (AttributeError, TypeError, ValueError) as exc:
        raise AnomalyTrainingError("anomaly estimator cannot score the feature matrix") from exc
    if values.shape != (len(features),) or not np.isfinite(values).all():
        raise AnomalyTrainingError("anomaly estimator produced invalid raw scores")
    return values


def canonical_anomaly_scores(raw_scores: NDArray[np.float64]) -> NDArray[np.float64]:
    """Reverse sklearn score direction so larger values always mean more anomalous."""

    values = np.asarray(raw_scores, dtype=np.float64)
    if values.ndim != 1 or not len(values) or not np.isfinite(values).all():
        raise AnomalyTrainingError("raw anomaly scores must be a finite non-empty vector")
    canonical = -values
    if not np.isfinite(canonical).all():
        raise AnomalyTrainingError("canonical anomaly scores are not finite")
    return canonical


def score_pipeline(
    estimator: Pipeline,
    features: NDArray[np.float64],
) -> tuple[NDArray[np.float64], NDArray[np.float64]]:
    raw = raw_score_samples(estimator, features)
    return raw, canonical_anomaly_scores(raw)
