"""Configured Isolation Forest production candidates."""

from __future__ import annotations

from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from aegishunt.ml.anomaly.config import IsolationForestCandidateConfig

PREPROCESSING_NAME = "standard_scaler"


def isolation_parameters(
    candidate: IsolationForestCandidateConfig,
) -> dict[str, bool | int | float | str]:
    return {
        "n_estimators": candidate.n_estimators,
        "max_samples": candidate.max_samples,
        "max_features": candidate.max_features,
        "bootstrap": candidate.bootstrap,
        "contamination": candidate.contamination,
        "n_jobs": candidate.n_jobs,
    }


def build_isolation_forest(
    candidate: IsolationForestCandidateConfig,
    *,
    random_seed: int,
) -> Pipeline:
    """Build an unfitted preprocessing/model path with external thresholding."""

    estimator = IsolationForest(
        **isolation_parameters(candidate),
        random_state=random_seed,
        warm_start=False,
    )
    return Pipeline((("scale", StandardScaler()), ("model", estimator)))
