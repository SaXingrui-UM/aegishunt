"""Explicit Phase 9 correlation failures."""

from aegishunt.errors import AegisHuntError


class CorrelationError(AegisHuntError):
    """Base failure for correlation contracts and execution."""


class CorrelationConfigError(CorrelationError):
    """A correlation policy is missing, unsafe, or invalid."""


class CorrelationInputError(CorrelationError):
    """Alert evidence cannot be safely correlated."""


class CorrelationPersistenceError(CorrelationError):
    """A deterministic group cannot be safely persisted."""
