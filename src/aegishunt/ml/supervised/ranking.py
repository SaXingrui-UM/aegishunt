"""Finite optional-metric handling for supervised selection policies."""

from __future__ import annotations

import math

from aegishunt.ml.supervised.errors import TrainingError


def maximize_optional_metric(value: float | None, *, name: str) -> float:
    """Return a finite score for maximization, ranking missing evidence last."""

    if value is None:
        return -math.inf
    numeric = float(value)
    if not math.isfinite(numeric):
        raise TrainingError(f"{name} must be finite when present")
    return numeric


def minimize_optional_metric(value: float | None, *, name: str) -> float:
    """Return a finite score for minimization, ranking missing evidence last."""

    if value is None:
        return math.inf
    numeric = float(value)
    if not math.isfinite(numeric):
        raise TrainingError(f"{name} must be finite when present")
    return numeric
