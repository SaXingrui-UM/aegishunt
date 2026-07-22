"""Explicit Phase 10 case-workflow failures."""

from aegishunt.errors import AegisHuntError


class CaseError(AegisHuntError):
    """Base failure for investigation-case operations."""


class CasePolicyError(CaseError):
    """Raised when the case/feedback policy is absent or invalid."""


class CaseEligibilityError(CaseError):
    """Raised when source evidence cannot safely create or extend a case."""


class CaseTransitionError(CaseError):
    """Raised for an unsupported case lifecycle transition."""


class CaseConflictError(CaseError):
    """Raised when an explicit mutation would silently overwrite analyst state."""


class CaseArtifactError(CaseError):
    """Raised when a case report artifact is unsafe or corrupt."""
