"""Explicit Phase 10 feedback and candidate failures."""

from aegishunt.errors import AegisHuntError


class FeedbackError(AegisHuntError):
    """Base failure for analyst-feedback operations."""


class FeedbackConflictError(FeedbackError):
    """Raised when feedback would silently overwrite a different analyst judgment."""


class FeedbackEligibilityError(FeedbackError):
    """Raised when source evidence or provenance is not eligible."""


class FeedbackArtifactError(FeedbackError):
    """Raised when an export or candidate artifact is unsafe or corrupt."""
