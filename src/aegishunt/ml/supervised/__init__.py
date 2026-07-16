"""Leakage-resistant supervised detection research pipeline."""

from aegishunt.ml.supervised.config import SupervisedTrainingConfig
from aegishunt.ml.supervised.data import SupervisedDatasetGate

__all__ = ["SupervisedDatasetGate", "SupervisedTrainingConfig"]
