"""Validation-only probability calibration with explicit method selection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

import numpy as np
from numpy.typing import NDArray
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss

from aegishunt.ml.supervised.config import SupervisedTrainingConfig
from aegishunt.ml.supervised.contracts import CalibrationResult
from aegishunt.ml.supervised.errors import TrainingError

CalibrationMethod = Literal["sigmoid", "isotonic"]


@dataclass(frozen=True, slots=True)
class ProbabilityCalibrator:
    """Stored validation-fitted mapping from raw score to calibrated probability."""

    method: CalibrationMethod
    estimator: object

    def transform(self, raw_scores: NDArray[np.float64]) -> NDArray[np.float64]:
        if self.method == "sigmoid":
            estimator = self.estimator
            if not isinstance(estimator, LogisticRegression):
                raise TrainingError("sigmoid calibrator state is invalid")
            probabilities = estimator.predict_proba(raw_scores.reshape(-1, 1))[:, 1]
        elif self.method == "isotonic":
            estimator = self.estimator
            if not isinstance(estimator, IsotonicRegression):
                raise TrainingError("isotonic calibrator state is invalid")
            probabilities = estimator.predict(raw_scores)
        else:
            raise TrainingError("unsupported stored calibration method")
        values = np.asarray(probabilities, dtype=np.float64)
        if not np.isfinite(values).all() or np.any((values < 0.0) | (values > 1.0)):
            raise TrainingError("calibrator produced invalid probabilities")
        return np.asarray(values, dtype=np.float64)


def _fit_method(
    method: CalibrationMethod,
    raw_scores: NDArray[np.float64],
    labels: NDArray[np.int64],
    *,
    random_seed: int,
) -> ProbabilityCalibrator:
    if method == "sigmoid":
        estimator = LogisticRegression(random_state=random_seed, solver="liblinear")
        estimator.fit(raw_scores.reshape(-1, 1), labels)
    elif method == "isotonic":
        estimator = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
        estimator.fit(raw_scores, labels)
    else:
        raise TrainingError("unsupported calibration method")
    return ProbabilityCalibrator(method=method, estimator=estimator)


def select_calibration(
    raw_scores: NDArray[np.float64],
    labels: NDArray[np.int64],
    config: SupervisedTrainingConfig,
) -> tuple[ProbabilityCalibrator, tuple[CalibrationResult, ...]]:
    """Choose calibration by validation Brier score, never test evidence."""

    if len(set(labels.tolist())) != 2:
        raise TrainingError("calibration requires both validation classes")
    counts = {label: int(np.sum(labels == label)) for label in (0, 1)}
    candidates: list[tuple[ProbabilityCalibrator, CalibrationResult]] = []
    evidence: list[CalibrationResult] = []
    for method in config.calibration_methods:
        if method == "isotonic" and min(counts.values()) < config.min_isotonic_samples_per_class:
            evidence.append(
                CalibrationResult(
                    method=method,
                    status="not_applicable",
                    failure_code="insufficient_validation_samples_per_class",
                )
            )
            continue
        try:
            calibrator = _fit_method(
                method,
                raw_scores,
                labels,
                random_seed=config.random_seed,
            )
            probabilities = calibrator.transform(raw_scores)
            result = CalibrationResult(
                method=method,
                status="passed",
                brier_score=float(brier_score_loss(labels, probabilities)),
            )
        except (FloatingPointError, TypeError, ValueError):
            result = CalibrationResult(
                method=method,
                status="failed",
                failure_code="calibration_fit_failed",
            )
        evidence.append(result)
        if result.status == "passed":
            candidates.append((calibrator, result))
    if not candidates:
        raise TrainingError("all calibration methods failed or were inapplicable")
    selected, _ = min(
        candidates,
        key=lambda item: (float(item[1].brier_score or 1.0), item[1].method),
    )
    return selected, tuple(evidence)
