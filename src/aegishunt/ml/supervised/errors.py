"""Explicit Phase 5 failures without sensitive runtime details."""

from aegishunt.errors import AegisHuntError


class SupervisedError(AegisHuntError):
    """Base failure for supervised experiment operations."""


class DatasetGateError(SupervisedError):
    """Phase 4 evidence is incomplete, inconsistent, or unsafe for training."""


class TrainingError(SupervisedError):
    """A controlled supervised training operation failed."""


class EvaluationError(SupervisedError):
    """Metrics or frozen-test evaluation inputs are invalid."""


class ArtifactError(SupervisedError):
    """A supervised experiment or model artifact cannot be safely used."""


class BundleIntegrityError(SupervisedError):
    """A system-generated model bundle failed authenticity or integrity checks."""


class PredictionError(SupervisedError):
    """Prediction input violates the stored model feature contract."""
