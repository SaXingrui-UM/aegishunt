"""Deterministic, evidence-preserving alert correlation."""

from aegishunt.correlation.config import load_correlation_policy
from aegishunt.correlation.grouping import correlate_alerts

__all__ = ["correlate_alerts", "load_correlation_policy"]
