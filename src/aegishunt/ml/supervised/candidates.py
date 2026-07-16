"""Required supervised candidates with model-specific preprocessing."""

from __future__ import annotations

from typing import Any

import numpy as np
from numpy.typing import NDArray
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from aegishunt.ml.supervised.config import Algorithm, ParameterValue
from aegishunt.ml.supervised.errors import TrainingError

PREPROCESSING_VERSION = "1.0.0"


def _normalized(parameters: dict[str, ParameterValue]) -> dict[str, Any]:
    return {key: None if value == "none" else value for key, value in parameters.items()}


def build_candidate(
    algorithm: Algorithm,
    parameters: dict[str, ParameterValue],
    *,
    random_seed: int,
) -> Pipeline:
    """Build one fresh estimator; no fitted state is shared across folds."""

    values = _normalized(parameters)
    if algorithm == "dummy":
        estimator = DummyClassifier(random_state=random_seed, **values)
        steps = [("model", estimator)]
    elif algorithm == "logistic_regression":
        estimator = LogisticRegression(random_state=random_seed, **values)
        steps = [("scale", StandardScaler()), ("model", estimator)]
    elif algorithm == "decision_tree":
        estimator = DecisionTreeClassifier(random_state=random_seed, **values)
        steps = [("model", estimator)]
    elif algorithm == "random_forest":
        estimator = RandomForestClassifier(random_state=random_seed, **values)
        steps = [("model", estimator)]
    elif algorithm == "hist_gradient_boosting":
        estimator = HistGradientBoostingClassifier(random_state=random_seed, **values)
        steps = [("model", estimator)]
    else:  # pragma: no cover - Literal and configuration validation make this defensive.
        raise TrainingError("unsupported supervised candidate")
    return Pipeline(steps)


def raw_positive_scores(
    estimator: Pipeline,
    features: NDArray[np.float64],
) -> NDArray[np.float64]:
    """Return an uncalibrated positive-class score, never label it a probability."""

    scores = np.asarray(estimator.predict_proba(features), dtype=np.float64)
    if scores.ndim != 2 or scores.shape[1] != 2:
        raise TrainingError("candidate did not produce binary class scores")
    positive = scores[:, 1]
    if not np.isfinite(positive).all():
        raise TrainingError("candidate produced a non-finite score")
    return np.asarray(positive, dtype=np.float64)
