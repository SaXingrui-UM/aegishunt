"""Explicit Phase 9 hypothesis-engine failures."""

from aegishunt.errors import AegisHuntError


class HypothesisError(AegisHuntError):
    """Base failure for hypothesis generation and lifecycle operations."""


class HypothesisGateError(HypothesisError):
    """Raised when an alert group cannot safely produce a hypothesis."""


class HypothesisTransitionError(HypothesisError):
    """Raised for an unsupported or automatic status transition."""
