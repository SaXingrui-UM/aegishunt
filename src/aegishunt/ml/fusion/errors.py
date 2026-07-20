"""Explicit Phase 7 failure types."""

from aegishunt.errors import AegisHuntError


class FusionError(AegisHuntError):
    """Base class for fusion and evaluation failures."""


class FusionConfigError(FusionError):
    """Raised when a pre-registered configuration is invalid."""


class FusionContractError(FusionError):
    """Raised when score or identity inputs violate the fusion contract."""


class FusionSelectionError(FusionError):
    """Raised when validation evidence cannot select a policy."""


class FusionDatasetError(FusionError):
    """Raised when controlled experiment evidence is unsafe or leaks."""


class FusionArtifactError(FusionError):
    """Raised when experiment or policy artifacts fail integrity checks."""
