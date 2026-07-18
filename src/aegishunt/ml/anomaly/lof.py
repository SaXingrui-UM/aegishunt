"""Novelty-mode Local Outlier Factor offline comparator."""

from __future__ import annotations

from sklearn.neighbors import LocalOutlierFactor
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from aegishunt.ml.anomaly.config import LofComparatorConfig


def lof_parameters(config: LofComparatorConfig) -> dict[str, bool | int | float | str]:
    return {
        "n_neighbors": config.n_neighbors,
        "metric": config.metric,
        "algorithm": config.algorithm,
        "leaf_size": config.leaf_size,
        "n_jobs": config.n_jobs,
        "novelty": True,
    }


def build_lof_comparator(config: LofComparatorConfig) -> Pipeline:
    """Build LOF for scoring unseen validation rows; never call fit_predict."""

    estimator = LocalOutlierFactor(**lof_parameters(config))
    return Pipeline((("scale", StandardScaler()), ("model", estimator)))
