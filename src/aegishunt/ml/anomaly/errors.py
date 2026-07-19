"""Explicit Phase 6 failure categories."""

from aegishunt.errors import AegisHuntError


class AnomalyError(AegisHuntError):
    """Base class for anomaly-engine failures safe to show to CLI users."""


class AnomalyDatasetError(AnomalyError):
    """Phase 4 evidence or the benign-only training boundary is invalid."""


class AnomalyTrainingError(AnomalyError):
    """An estimator, normalizer, threshold, or selection operation failed."""


class AnomalyEvaluationError(AnomalyError):
    """An anomaly metric or frozen evaluation input is invalid."""


class AnomalyArtifactError(AnomalyError):
    """Experiment evidence or a model bundle failed integrity checks."""


class AnomalyPredictionError(AnomalyError):
    """An anomaly scoring request violates the saved inference contract."""
